#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/trust_store.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/sha.hpp>
#include <algorithm>
#include <chrono>

namespace vanetza
{
namespace security
{
namespace
{

boost::optional<StartAndEndValidity> extract_validity_time(const Certificate& certificate)
{
    boost::optional<StartAndEndValidity> restriction;

    for (auto& validity_restriction : certificate.validity_restriction) {
        ValidityRestrictionType type = get_type(validity_restriction);

        if (type == ValidityRestrictionType::Time_Start_And_End) {
            // reject more than one restriction
            if (restriction) {
                return boost::none;
            }
            restriction = boost::get<StartAndEndValidity>(validity_restriction);

            // check if certificate validity restriction timestamps are logically correct
            if (restriction->start_validity >= restriction->end_validity) {
                return boost::none;
            }
        } else if (type == ValidityRestrictionType::Time_End) {
            // must not be used, no certificate profile allows it
            return boost::none;
        } else if (type == ValidityRestrictionType::Time_Start_And_Duration) {
            // must not be used, no certificate profile allows it
            return boost::none;
        }
    }

    return restriction;
}

bool check_time_consistency(const Certificate& certificate, const Certificate& signer)
{
    boost::optional<StartAndEndValidity> certificate_time = extract_validity_time(certificate);
    boost::optional<StartAndEndValidity> signer_time = extract_validity_time(signer);

    if (!certificate_time || !signer_time) {
        return false;
    }

    if (signer_time->start_validity > certificate_time->start_validity) {
        return false;
    }

    if (signer_time->end_validity < certificate_time->end_validity) {
        return false;
    }

    return true;
}

bool check_time_consistency(const CertificateV3& certificate, const CertificateV3& signer)
{
    boost::optional<StartAndEndValidity> certificate_time = certificate.get_start_and_end_validity();
    boost::optional<StartAndEndValidity> signer_time = signer.get_start_and_end_validity();

    if (!certificate_time || !signer_time) {
        return false;
    }

    if (signer_time->start_validity > certificate_time->start_validity) {
        return false;
    }

    if (signer_time->end_validity < certificate_time->end_validity) {
        return false;
    }

    return true;
}

bool check_time_consistency(const CertificateVariant& certificate, const CertificateVariant& signer)
{

    struct canonical_visitor : public boost::static_visitor<boost::optional<StartAndEndValidity>>
        {
            boost::optional<StartAndEndValidity> operator()(const Certificate& cert) const
            {
                return extract_validity_time(cert);
            }

            boost::optional<StartAndEndValidity> operator()(const CertificateV3& cert) const
            {
                return cert.get_start_and_end_validity();
            }
        };
    boost::optional<StartAndEndValidity> certificate_time = boost::apply_visitor(canonical_visitor(), certificate);//certificate.get_start_and_end_validity();
    boost::optional<StartAndEndValidity> signer_time = boost::apply_visitor(canonical_visitor(), signer);

    if (!certificate_time || !signer_time) {
        return false;
    }

    if (signer_time->start_validity > certificate_time->start_validity) {
        return false;
    }

    if (signer_time->end_validity < certificate_time->end_validity) {
        return false;
    }

    return true;
}

std::list<ItsAid> extract_application_identifiers(const Certificate& certificate)
{
    std::list<ItsAid> aids;

    auto certificate_type = certificate.subject_info.subject_type;
    if (certificate_type == SubjectType::Authorization_Ticket) {
        auto list = certificate.get_attribute<SubjectAttributeType::ITS_AID_SSP_List>();
        if (list) {
            for (auto& item : *list) {
                aids.push_back(item.its_aid.get());
            }
        }
    } else {
        auto list = certificate.get_attribute<SubjectAttributeType::ITS_AID_List>();
        if (list) {
            for (auto& item : *list) {
                aids.push_back(item.get());
            }
        }
    }

    return aids;
}

bool check_permission_consistency_intern(std::list<ItsAid>& certificate_aids, std::list<ItsAid>& signer_aids){
    auto compare = [](ItsAid a, ItsAid b) { return a < b; };

    certificate_aids.sort(compare);
    signer_aids.sort(compare);

    return std::includes(signer_aids.begin(), signer_aids.end(), certificate_aids.begin(), certificate_aids.end());
}

bool check_permission_consistency(const Certificate& certificate, const Certificate& signer)
{
    auto certificate_aids = extract_application_identifiers(certificate);
    auto signer_aids = extract_application_identifiers(signer);
    return check_permission_consistency_intern(certificate_aids, signer_aids);
}

using PsidSspRangeMap = std::map<Psid_t, const SspRange_t *>;

bool contains_octet_string(const SequenceOfOctetString_t &sequence_of_octet_string, const OCTET_STRING_t &octet_string)
{
    const auto &list = sequence_of_octet_string.list;
    for (int i = 0; i < list.count; i++) {
        if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, list.array[i], &octet_string) == 0) {
            return true;
        }
    }

    return false;
}

bool contains_empty_octet_string(const SequenceOfOctetString_t &sequence_of_octet_string)
{
    const auto &list = sequence_of_octet_string.list;
    for (int i = 0; i < list.count; i++) {
        if (list.array[i]->size == 0) {
            return true;
        }
    }

    return false;
}

bool validate_bitmap_ssp(const BitmapSspRange_t &signer_ssp_range, const BitmapSsp_t &certificate_ssp)
{
    // The bitmask in the signer SSP range restricts the certificate SSP.
    // For every bit set in the bitmask, the corresponding bits of
    // the certificate SSP and the signer SSP range value field must be equal.

    const auto &signer_ssp_range_bitmask = signer_ssp_range.sspBitmask;
    const auto &signer_ssp_range_value = signer_ssp_range.sspValue;
    const auto &certificate_ssp_value = certificate_ssp;

    // Check lenghts
    if (signer_ssp_range_value.size != certificate_ssp_value.size ||
        signer_ssp_range_bitmask.size != certificate_ssp_value.size) {
        return false;
    }

    // Check values
    for (size_t i = 0; i < certificate_ssp_value.size; i++) {
        if ((signer_ssp_range_bitmask.buf[i] & certificate_ssp_value.buf[i]) !=
            (signer_ssp_range_bitmask.buf[i] & signer_ssp_range_value.buf[i])) {
            return false;
        }
    }

    return true;
}

bool validate_app_permisions_on_psid_group_permissions(
    const std::vector<const PsidSsp_t *> &certificate_app_permissions,
    const PsidSspRangeMap &signer_issue_permissions_map,
    bool default_granted)
{
    // Check if the certificate application permissions are consistent with the
    // signer issue permissions
    for (const auto &certificate_app_permission : certificate_app_permissions) {
        // Find the PSID in the signer issue permissions
        const auto signer_issue_ssp_range =
            signer_issue_permissions_map.find(certificate_app_permission->psid);

        // If the PSID is not found, check if all permissions are allowed by default
        if (signer_issue_ssp_range == signer_issue_permissions_map.end()) {
            if (default_granted) {
                continue;
            } else {
                return false;
            }
        }

        // Check if the signer allows all permissions for the PSID
        const auto &signer_ssp_range = signer_issue_ssp_range->second;
        if (nullptr == signer_ssp_range || signer_ssp_range->present == SspRange_PR_all) {
            continue;
        }

        // If the SSP in the application permission is omitted,
        // check for a issuer SSP range of type "opaque".
        // It should contain an empty octet string,
        // see IEEE 1609.2-2022 Section 6.4.28.
        const auto &certificate_app_ssp = certificate_app_permission->ssp;
        if (nullptr == certificate_app_ssp) {
            if (signer_ssp_range->present == SspRange_PR_opaque &&
                contains_empty_octet_string(signer_ssp_range->choice.opaque)) {
                continue;
            } else {
                return false;
            }
        }

        // Validation of opaque and bitmap application permission types
        // See IEEE 1609.2-2022 Section 6.4.29 and 6.4.30
        if (certificate_app_ssp->present == ServiceSpecificPermissions_PR_opaque &&
            signer_ssp_range->present == SspRange_PR_opaque &&
            contains_octet_string(
                signer_ssp_range->choice.opaque, certificate_app_ssp->choice.opaque)) {
            continue;
        }

        if (certificate_app_ssp->present == ServiceSpecificPermissions_PR_bitmapSsp &&
            signer_ssp_range->present == SspRange_PR_bitmapSspRange &&
            validate_bitmap_ssp(signer_ssp_range->choice.bitmapSspRange,
                                certificate_app_ssp->choice.bitmapSsp)) {
            continue;
        }

        return false;
    }

    return true;
}

bool check_permission_consistency(const CertificateV3& certificate, const CertificateV3& signer)
{
    // Validate certificate permissions, IEEE 1609.2-2022 Section 5.1.2.4 and 6.4.8
    // The field certRequestPermissions is not used for ETSI certificates

    // Save the PSID Groups to a list of Psid_t -> SspRange_t* maps
    // for easy comparison with the certificate permissions
    const auto signer_issue_permissions = signer.get_issue_permissions();
    bool default_granted = false;
    std::list<PsidSspRangeMap> signer_issue_permissions_map_list;
    if (!signer_issue_permissions.empty()) {
        for (const auto *const &psid_group_permissions: signer_issue_permissions) {
            const auto &subject_permissions = psid_group_permissions->subjectPermissions;

            // Check if permissions are granted by default
            if (subject_permissions.present == SubjectPermissions_PR_all) {
                default_granted = true;
            } else if (subject_permissions.present != SubjectPermissions_PR_explicit) {
                continue;
            }

            // Save the PSID Group
            signer_issue_permissions_map_list.emplace_back();
            auto &psid_ssp_range_map = signer_issue_permissions_map_list.back();
            const auto &explicit_permissions = subject_permissions.choice.Explicit.list;
            for (int i = 0; i < explicit_permissions.count; i++) {
                const auto *psid_ssp_range = explicit_permissions.array[i];
                psid_ssp_range_map[psid_ssp_range->psid] = psid_ssp_range->sspRange;
            }
        }
    }

    const auto certificate_app_permissions = certificate.get_app_permissions();
    if (!certificate_app_permissions.empty()) {
        // Validate application permissions, try every signer issue PSID Group
        bool certificate_app_permissions_granted = false;
        for (const auto &signer_issue_permissions_map: signer_issue_permissions_map_list) {
            certificate_app_permissions_granted =
                validate_app_permisions_on_psid_group_permissions(
                    certificate_app_permissions, signer_issue_permissions_map,
                    default_granted);
            if (certificate_app_permissions_granted) {
                break;
            }
        }

        if (!certificate_app_permissions_granted) {
            return false;
        }
    }

    return true;
}

bool check_permission_consistency(const CertificateVariant& certificateVariant, const CertificateVariant& signerVariant)
{
    struct canonical_visitor : public boost::static_visitor<bool>
        {
            bool operator()(const Certificate& certificate, const Certificate& signer) const
            {
                return check_permission_consistency(certificate, signer);
            }

            bool operator()(const CertificateV3& certificate, const CertificateV3& signer) const
            {
                return check_permission_consistency(certificate, signer);
            }

            bool operator()(const Certificate&, const CertificateV3&) const
            {
                return false;
            }

            bool operator()(const CertificateV3&, const Certificate&) const
            {
                return false;
            }
        };
    return boost::apply_visitor(canonical_visitor(), certificateVariant, signerVariant);
}

bool check_subject_assurance_consistency_intern(const SubjectAssurance* certificate_assurance, const SubjectAssurance* signer_assurance){
    if (!certificate_assurance || !signer_assurance) {
        return false;
    }

    // See TS 103 096-2 v1.3.1, section 5.2.7.11 + 5.3.5.17 and following
    if (certificate_assurance->assurance() > signer_assurance->assurance()) {
        return false;
    } else if (certificate_assurance->assurance() == signer_assurance->assurance()) {
        if (certificate_assurance->confidence() > signer_assurance->confidence()) {
            return false;
        }
    }

    return true;
}

bool check_subject_assurance_consistency(const Certificate& certificate, const Certificate& signer)
{
    auto certificate_assurance = certificate.get_attribute<SubjectAttributeType::Assurance_Level>();
    auto signer_assurance = signer.get_attribute<SubjectAttributeType::Assurance_Level>();
    return check_subject_assurance_consistency_intern(certificate_assurance, signer_assurance);

}

bool check_subject_assurance_consistency(const CertificateV3& certificate, const CertificateV3& signer)
{
    auto certificate_assurance = certificate.get_subject_assurance();
    auto signer_assurance = signer.get_subject_assurance();
    return check_subject_assurance_consistency_intern(certificate_assurance.get(), signer_assurance.get());
}

bool check_subject_assurance_consistency(const CertificateVariant& certificate, const CertificateVariant& signer){
    struct canonical_visitor : public boost::static_visitor<const SubjectAssurance*>
        {
            const SubjectAssurance* operator()(const Certificate& cert) const
            {
                return cert.get_attribute<SubjectAttributeType::Assurance_Level>();
            }

            const SubjectAssurance* operator()(const CertificateV3& cert) const
            {
                return cert.get_subject_assurance().get();
            }
        };
    auto certificate_assurance = boost::apply_visitor(canonical_visitor(), certificate);
    auto signer_assurance = boost::apply_visitor(canonical_visitor(), signer);
    return check_subject_assurance_consistency_intern(certificate_assurance, signer_assurance);
}

bool check_region_consistency_intern(const GeographicRegion* certificate_region, const GeographicRegion* signer_region) {
    if (!signer_region) {
        return true;
    }

    if (!certificate_region) {
        return false;
    }

    return is_within(*certificate_region, *signer_region);
}


bool check_region_consistency(const Certificate& certificate, const Certificate& signer)
{
    auto certificate_region = certificate.get_restriction<ValidityRestrictionType::Region>();
    auto signer_region = signer.get_restriction<ValidityRestrictionType::Region>();
    return check_region_consistency_intern(certificate_region, signer_region);

}

bool check_region_consistency(const CertificateV3& certificate, const CertificateV3& signer)
{
    auto certificate_region = certificate.get_geographic_region();
    auto signer_region = signer.get_geographic_region();
    return check_region_consistency_intern(certificate_region.get(), signer_region.get());
}

bool check_region_consistency(const CertificateVariant& certificate, const CertificateVariant& signer){
    struct canonical_visitor : public boost::static_visitor<const GeographicRegion*>
        {
            const GeographicRegion* operator()(const Certificate& cert) const
            {
                return cert.get_restriction<ValidityRestrictionType::Region>();
            }

            const GeographicRegion* operator()(const CertificateV3& cert) const
            {
                return cert.get_geographic_region().get();
            }
        };
    auto certificate_region = boost::apply_visitor(canonical_visitor(), certificate);
    auto signer_region = boost::apply_visitor(canonical_visitor(), signer);
    return check_region_consistency_intern(certificate_region, signer_region);
}

bool check_consistency(const Certificate& certificate, const Certificate& signer)
{
    if (!check_time_consistency(certificate, signer)) {
        return false;
    }

    if (!check_permission_consistency(certificate, signer)) {
        return false;
    }

    if (!check_subject_assurance_consistency(certificate, signer)) {
        return false;
    }

    if (!check_region_consistency(certificate, signer)) {
        return false;
    }

    return true;
}

bool check_consistency(const CertificateV3& certificate, const CertificateV3& signer)
{
    if (!check_time_consistency(certificate, signer)) {
        return false;
    }

    if (!check_permission_consistency(certificate, signer)) {
        return false;
    }

    if (!check_subject_assurance_consistency(certificate, signer)) {
        return false;
    }

    if (!check_region_consistency(certificate, signer)) {
        return false;
    }

    return true;
}

bool check_consistency(const CertificateVariant& certificate, const CertificateVariant& signer)
{
    if (!check_time_consistency(certificate, signer)) {
        return false;
    }

    if (!check_permission_consistency(certificate, signer)) {
        return false;
    }

    if (!check_subject_assurance_consistency(certificate, signer)) {
        return false;
    }

    if (!check_region_consistency(certificate, signer)) {
        return false;
    }

    return true;
}

} // namespace

DefaultCertificateValidator::DefaultCertificateValidator(Backend& backend, CertificateCache& cert_cache, const TrustStore& trust_store) :
    m_crypto_backend(backend),
    m_cert_cache(cert_cache),
    m_trust_store(trust_store)
{
}

CertificateValidity DefaultCertificateValidator::check_certificate(const CertificateVariant& certificate){
    class certificate_visitor : public boost::static_visitor<CertificateValidity>
        {
            public:
                certificate_visitor(DefaultCertificateValidator& validator): validator_(validator){}
                CertificateValidity operator()(const Certificate& cert) const
                {
                    return validator_.check_certificate(cert);
                }

                CertificateValidity operator()(const CertificateV3& cert) const
                {
                    return validator_.check_certificate(cert);
                }
            private:
                DefaultCertificateValidator& validator_;
        };
    return boost::apply_visitor(certificate_visitor(*this), certificate);
}


CertificateValidity DefaultCertificateValidator::check_certificate(const Certificate& certificate)
{
    if (!extract_validity_time(certificate)) {
        return CertificateInvalidReason::Broken_Time_Period;
    }

    if (!certificate.get_attribute<SubjectAttributeType::Assurance_Level>()) {
        return CertificateInvalidReason::Missing_Subject_Assurance;
    }

    SubjectType subject_type = certificate.subject_info.subject_type;

    // check if subject_name is empty if certificate is authorization ticket
    if (subject_type == SubjectType::Authorization_Ticket && 0 != certificate.subject_info.subject_name.size()) {
        return CertificateInvalidReason::Invalid_Name;
    }

    if (get_type(certificate.signer_info) != SignerInfoType::Certificate_Digest_With_SHA256) {
        return CertificateInvalidReason::Invalid_Signer;
    }
    HashedId8 signer_hash = boost::get<HashedId8>(certificate.signer_info);

    // try to extract ECDSA signature
    boost::optional<EcdsaSignature> sig = extract_ecdsa_signature(certificate.signature);
    if (!sig) {
        return CertificateInvalidReason::Missing_Signature;
    }

    // create buffer of certificate
    ByteBuffer binary_cert = convert_for_signing(certificate);

    // authorization tickets may only be signed by authorization authorities
    if (subject_type == SubjectType::Authorization_Ticket) {
        for (auto& possible_signer : m_cert_cache.lookup(signer_hash, SubjectType::Authorization_Authority)) {
            auto verification_key = get_public_key(possible_signer, m_crypto_backend);
            if (!verification_key) {
                continue;
            }

            if (m_crypto_backend.verify_data(verification_key.get(), binary_cert, sig.get())) {
                if (!check_consistency(certificate, possible_signer)) {
                    return CertificateInvalidReason::Inconsistent_With_Signer;
                }

                return CertificateValidity::valid();
            }
        }
    }

    // authorization authorities may only be signed by root CAs
    // Note: There's no clear specification about this, but there's a test for it in 5.2.7.12.4 of TS 103 096-2 V1.3.1
    if (subject_type == SubjectType::Authorization_Authority) {
        for (auto& possible_signer : m_trust_store.lookup(signer_hash)) {
            auto verification_key = get_public_key(possible_signer, m_crypto_backend);
            if (!verification_key) {
                continue;
            }

            if (m_crypto_backend.verify_data(verification_key.get(), binary_cert, sig.get())) {
                if (!check_consistency(certificate, possible_signer)) {
                    return CertificateInvalidReason::Inconsistent_With_Signer;
                }

                return CertificateValidity::valid();
            }
        }
    }

    return CertificateInvalidReason::Unknown_Signer;
}

CertificateValidity DefaultCertificateValidator::check_certificate(const CertificateV3& certificate)
{

    HashedId8 signer_hash = certificate.get_issuer_identifier();

    if (certificate.is_self_signed()) {
        bool is_trusted = !m_trust_store.lookup(signer_hash).empty();
        return is_trusted ? CertificateValidity::valid() : CertificateInvalidReason::Unknown_Signer;
    }

    if (signer_hash == HashedId8{{0,0,0,0,0,0,0,0}}) {
        return CertificateInvalidReason::Invalid_Signer;
    }

    // try to extract ECDSA signature
    boost::optional<EcdsaSignature> sig = extract_ecdsa_signature(certificate.get_signature());
    if (!sig) {
        return CertificateInvalidReason::Missing_Signature;
    }

    // create buffer of certificate
    ByteBuffer binary_cert = certificate.convert_for_signing();

    // authorization tickets may only be signed by authorization authorities

    for (auto& possible_signer : m_cert_cache.lookup(signer_hash)) {
        CertificateV3 signer_cert = boost::get<CertificateV3>(possible_signer);
        auto verification_key = signer_cert.get_public_key(m_crypto_backend);
        auto curve_name = signer_cert.get_public_key_curve_name();
        if (!verification_key || !curve_name) {
            continue;
        }

        ByteBuffer signature_input = calculate_sha_signature_inputV3(binary_cert, signer_cert, *curve_name);
        if (m_crypto_backend.verify_data(verification_key.get(), signature_input, sig.get(), curve_name.get())) {
            if (!check_consistency(certificate, possible_signer)) {
                return CertificateInvalidReason::Inconsistent_With_Signer;
            }

            return CertificateValidity::valid();
        }
    }

    // authorization authorities may only be signed by root CAs
    // Note: There's no clear specification about this, but there's a test for it in 5.2.7.12.4 of TS 103 096-2 V1.3.1
    for (auto& possible_signer : m_trust_store.lookup(signer_hash)) {
        CertificateV3 signer_cert = boost::get<CertificateV3>(possible_signer);
        auto verification_key = signer_cert.get_public_key(m_crypto_backend);
        auto curve_name = signer_cert.get_public_key_curve_name();
        if (!verification_key || !curve_name) {
            continue;
        }

        ByteBuffer signature_input = calculate_sha_signature_inputV3(binary_cert, signer_cert, *curve_name);
        if (m_crypto_backend.verify_data(verification_key.get(), signature_input, sig.get(), curve_name.get())) {
            if (!check_consistency(certificate, possible_signer)) {
                return CertificateInvalidReason::Inconsistent_With_Signer;
            }

            return CertificateValidity::valid();
        }
    }

    return CertificateInvalidReason::Unknown_Signer;
}


} // namespace security
} // namespace vanetza
