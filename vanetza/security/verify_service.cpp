#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/certificate_validator.hpp>
#include <vanetza/security/sign_header_policy.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/verify_service.hpp>
#include <vanetza/security/sha.hpp>
#include <vanetza/asn1/support/INTEGER.h>
#include <vanetza/asn1/utils.hpp>
#include <memory>
#include <boost/optional.hpp>
#include <chrono>

namespace vanetza
{
namespace security
{
namespace
{

bool check_generation_time(const SecuredMessageV2& message, Clock::time_point now)
{
    using namespace std::chrono;

    bool valid = false;
    const Time64* generation_time = message.header_field<HeaderFieldType::Generation_Time>();
    if (generation_time) {
        // Values are picked from C2C-CC Basic System Profile v1.1.0, see RS_BSP_168
        static const auto generation_time_future = milliseconds(40);
        static const Clock::duration generation_time_past_default = minutes(10);
        static const Clock::duration generation_time_past_ca = seconds(2);
        auto generation_time_past = generation_time_past_default;

        const IntX* its_aid = message.header_field<HeaderFieldType::Its_Aid>();
        if (its_aid && aid::CA == *its_aid) {
            generation_time_past = generation_time_past_ca;
        }

        if (*generation_time > convert_time64(now + generation_time_future)) {
            valid = false;
        } else if (*generation_time < convert_time64(now - generation_time_past)) {
            valid = false;
        } else {
            valid = true;
        }
    }

    return valid;
}

bool check_generation_time(const SecuredMessageV3& message, Clock::time_point now)
{
    using namespace std::chrono;

    bool valid = false;
    std::shared_ptr<Time64> generation_time = message.get_generation_time();
    if (generation_time) {
        // Values are picked from C2C-CC Basic System Profile v1.1.0, see RS_BSP_168
        static const auto generation_time_future = milliseconds(40);
        static const Clock::duration generation_time_past_default = minutes(10);
        static const Clock::duration generation_time_past_ca = seconds(2);
        auto generation_time_past = generation_time_past_default;

        const Psid_t psid = message.get_psid();
        if (aid::CA == psid) {
            generation_time_past = generation_time_past_ca;
        } else if (aid::CTL == psid) {
            // CTLs can be valid for about 4 months
            generation_time_past = hours(3000);
        } else if (aid::CRL == psid) {
            // This is not specified, so we assume this is equal
            // to the maximum validity of a CA certificate (5 years)
            generation_time_past = hours(43800);
        }

        if (*generation_time > convert_time64(now + generation_time_future)) {
            valid = false;
        } else if (*generation_time < convert_time64(now - generation_time_past)) {
            valid = false;
        } else {
            valid = true;
        }
    }

    return valid;
}

bool check_generation_location(const SecuredMessageV2& message, const Certificate& cert)
{
    const IntX* its_aid = message.header_field<HeaderFieldType::Its_Aid>();
    if (its_aid && aid::CA == *its_aid) {
        return true; // no check required for CAMs, field not even allowed
    }

    const ThreeDLocation* generation_location = message.header_field<HeaderFieldType::Generation_Location>();
    if (generation_location) {
        auto region = cert.get_restriction<ValidityRestrictionType::Region>();

        if (!region || get_type(*region) == RegionType::None) {
            return true;
        }

        return is_within(TwoDLocation(*generation_location), *region);
    }

    return false;
}

bool check_generation_location(const SecuredMessageV3& message, const CertificateV3& cert)
{
    const Psid_t psid = message.get_psid();
    if (aid::CA == psid) {
        return true; // no check required for CAMs, field not even allowed
    }

    std::shared_ptr<ThreeDLocation> generation_location = message.get_generation_location();
    if (generation_location) {
        std::shared_ptr<GeographicRegion> region = cert.get_geographic_region();

        if (get_type(*region) == RegionType::None) {
            return true;
        }
        return is_within(TwoDLocation(*generation_location), *region);
    }

    return false;
}

bool check_generation_location(const SecuredMessageVariant& message, const CertificateVariant& cert)
{
    struct its_aid_visitor : public boost::static_visitor<std::unique_ptr<long>>
        {
            std::unique_ptr<long> operator()(const SecuredMessageV2& message) const
            {
                const IntX* its_aid = message.header_field<HeaderFieldType::Its_Aid>();
                if(!its_aid){
                    return nullptr;
                }
                return std::move(std::unique_ptr<long>(new long(its_aid->get())));
            }

            std::unique_ptr<long> operator()(const SecuredMessageV3& message) const
            {
                return std::move(std::unique_ptr<long>(new long(message.get_psid())));
            }
        };
    std::unique_ptr<long> its_aid = boost::apply_visitor(its_aid_visitor(), message);
    if (its_aid && aid::CA == *its_aid) {
        return true; // no check required for CAMs, field not even allowed
    }
    struct three_d_visitor : public boost::static_visitor<std::shared_ptr<const ThreeDLocation>>
        {
            std::shared_ptr<const ThreeDLocation> operator()(const SecuredMessageV2& message) const
            {
                return std::shared_ptr<const ThreeDLocation>(message.header_field<HeaderFieldType::Generation_Location>());
            }

            std::shared_ptr<const ThreeDLocation> operator()(const SecuredMessageV3& message) const
            {
                return message.get_generation_location();
            }
        };
    struct region_visitor : public boost::static_visitor<std::shared_ptr<const GeographicRegion>>
        {
            std::shared_ptr<const GeographicRegion> operator()(const Certificate& cert) const
            {
                return std::shared_ptr<const GeographicRegion>(cert.get_restriction<ValidityRestrictionType::Region>());
            }

            std::shared_ptr<const GeographicRegion> operator()(const CertificateV3& cert) const
            {
                return cert.get_geographic_region();
            }
        };

    std::shared_ptr<const ThreeDLocation> generation_location = boost::apply_visitor(three_d_visitor(), message);
    if (generation_location) {
        auto region = boost::apply_visitor(region_visitor(), cert);

        if (!region || get_type(*region) == RegionType::None) {
            return true;
        }

        return is_within(TwoDLocation(*generation_location), *region);
    }

    return false;
}


bool check_certificate_time_intern(const vanetza::security::StartAndEndValidity* time, Clock::time_point now){
    auto time_now = convert_time32(now);

    if (!time) {
        return false; // must be present
    }

    if (time->start_validity > time_now || time->end_validity < time_now) {
        return false; // premature or outdated
    }

    return true;
}

bool check_certificate_time(const Certificate& certificate, Clock::time_point now)
{
    const vanetza::security::StartAndEndValidity* time = certificate.get_restriction<ValidityRestrictionType::Time_Start_And_End>();
    return check_certificate_time_intern(time, now);

}

bool check_certificate_time(const CertificateV3& certificate, Clock::time_point now)
{
    auto time = certificate.get_start_and_end_validity();
    return check_certificate_time_intern(&time, now);
} // Test to be written

bool check_certificate_time(CertificateVariant& certificate, Clock::time_point now)
{
    struct canonical_visitor : public boost::static_visitor<bool>
        {
            canonical_visitor(Clock::time_point now): now_(now){}
            bool operator()(const Certificate& certificate) const
            {
                return check_certificate_time(certificate, now_);
            }

            bool operator()(const CertificateV3& certificate) const
            {
                return check_certificate_time(certificate, now_);
            }
            Clock::time_point now_;
        };
    return boost::apply_visitor(canonical_visitor(now), certificate);
}

bool check_certificate_region_intern(const vanetza::security::GeographicRegion* region, const PositionFix& position){
    if (!region || get_type(*region) == RegionType::None) {
        return true;
    }

    if (!position.confidence) {
        return false; // cannot check region restrictions without good position fix
    }

    return is_within(TwoDLocation(position.latitude, position.longitude), *region);
}

bool check_certificate_region(const Certificate& certificate, const PositionFix& position)
{
    auto region = certificate.get_restriction<ValidityRestrictionType::Region>();
    return check_certificate_region_intern(region, position);
}

bool check_certificate_region(const CertificateV3& certificate, const PositionFix& position)
{
    auto region = certificate.get_geographic_region();
    return check_certificate_region_intern(region.get(), position);
} // Test to be written

bool check_certificate_region(CertificateVariant& certificate, const PositionFix& position)
{
    struct canonical_visitor : public boost::static_visitor<bool>
        {
            canonical_visitor(const PositionFix& position): position_(position){}
            bool operator()(const Certificate& certificate) const
            {
                return check_certificate_region(certificate, position_);
            }

            bool operator()(const CertificateV3& certificate) const
            {
                return check_certificate_region(certificate, position_);
            }
            const PositionFix& position_;
        };
    return boost::apply_visitor(canonical_visitor(position), certificate);
}

bool assign_permissions(const Certificate& certificate, VerifyConfirm& confirm)
{
    for (auto& subject_attribute : certificate.subject_attributes) {
        if (get_type(subject_attribute) != SubjectAttributeType::ITS_AID_SSP_List) {
            continue;
        }

        auto& permissions = boost::get<std::list<ItsAidSsp> >(subject_attribute);
        for (auto& permission : permissions) {
            if (permission.its_aid == confirm.its_aid) {
                confirm.permissions = permission.service_specific_permissions;
                return true;
            }
        }

        break;
    }

    return false;
}

bool assign_permissions(const CertificateV3& certificate, VerifyConfirm& confirm)
{
    const std::vector<const PsidSsp_t *> app_prermissions =
        certificate.get_app_permissions();

    for (const PsidSsp_t *const psid_ssp : app_prermissions) {
        if (psid_ssp->psid != confirm.its_aid) {
            continue;
        }

        confirm.permissions = {};
        const ServiceSpecificPermissions_t *const ssp = psid_ssp->ssp;
        if (nullptr == ssp) {
            return true;
        }

        switch (ssp->present)
        {
        case ServiceSpecificPermissions_PR_opaque:
            confirm.permissions = asn1::OCTET_STRING_to_ByteBuffer(ssp->choice.opaque);
            break;
        case ServiceSpecificPermissions_PR_bitmapSsp:
            confirm.permissions = asn1::OCTET_STRING_to_ByteBuffer(ssp->choice.bitmapSsp);
            break;
        default:
            break;
        }

        return true;
    }
    return false;
}

bool assign_permissions(const vanetza::security::CertificateVariant& certificate, vanetza::security::VerifyConfirm& confirm)
{

    struct canonical_visitor : public boost::static_visitor<bool>
    {
        canonical_visitor(vanetza::security::VerifyConfirm& confirm): confirm_(confirm){}
        bool operator()(const Certificate& cert) const
        {
            return assign_permissions(cert, confirm_);
        }
        bool operator()(const CertificateV3& cert) const
        {
            return assign_permissions(cert, confirm_);
        }
        vanetza::security::VerifyConfirm& confirm_;
    };

    bool assigned = boost::apply_visitor(canonical_visitor(confirm), certificate);
    return assigned;

}


} // namespace

VerifyConfirm verify_v3(const VerifyRequest &request,
                        const Runtime &rt,
                        const boost::optional<CertificateProvider&> cert_provider,
                        const boost::optional<CertificateValidator&> certs,
                        Backend &backend,
                        boost::optional<CertificateCache&> cert_cache,
                        boost::optional<SignHeaderPolicy&> sign_policy,
                        const boost::optional<PositionProvider&> positioning)
{
    VerifyConfirm confirm;
    const SecuredMessageV3 &secured_message = boost::get<SecuredMessageV3>(request.secured_message);

    if (!secured_message.is_signed_message()) {
        confirm.report = VerificationReport::Unsigned_Message;
        return confirm;
    }

    if (3 != secured_message.protocol_version()) {
        confirm.report = VerificationReport::Incompatible_Protocol;
        return confirm;
    }


    if (cert_provider && sign_policy) {
        if (cert_provider->version() != 3){
            confirm.report = VerificationReport::Incompatible_Protocol;
            return confirm;
        }
        std::list<HashedId3> requested_certs = secured_message.get_inline_p2pcd_Request();
        if (requested_certs.size() > 0) {
            for (auto& requested_cert : requested_certs) {
                if (truncate(boost::get<CertificateV3>(cert_provider->own_certificate()).calculate_hash()) == requested_cert) {
                    sign_policy->request_certificate();
                }

                for (auto& cert : cert_provider->own_chain()) {
                    if (truncate(boost::get<CertificateV3>(cert).calculate_hash()) == requested_cert) {
                        sign_policy->request_certificate_chain();
                    }
                }
            }
        }
    }


    const IntX its_aid = IntX(secured_message.get_psid());
    confirm.its_aid = its_aid.get();

    const boost::optional<SignerInfo> signer_info = secured_message.get_signer_info();
    std::list<CertificateVariant> possible_certificates;
    bool possible_certificates_from_cache = false;

    // use a dummy hash for initialization
    HashedId8 signer_hash;
    signer_hash.fill(0x00);

    if (signer_info) {
        std::list<CertificateVariant> chain;
        auto signer_info_type = get_type(*signer_info);
        switch (signer_info_type) {
            case SignerInfoType::Certificate: {
                possible_certificates.push_back(boost::get<CertificateVariant>(*signer_info));
                signer_hash = calculate_hash(boost::get<CertificateVariant>(*signer_info));

                if (sign_policy && cert_cache && confirm.its_aid == aid::CA &&
                    cert_cache->lookup(signer_hash).empty()) {
                    // Previously unknown certificate, send own certificate in next
                    // CAM See TS 103 097 v1.2.1, section 7.1, 1st bullet, 3rd dash
                    sign_policy->request_certificate();
                }
                break;
            }
            case SignerInfoType::Certificate_Digest_With_SHA256: {
                signer_hash = boost::get<HashedId8>(*signer_info);
                if (cert_cache) {
                    std::list<CertificateVariant> temp_variant_cache = cert_cache->lookup(signer_hash);
                    for (const auto& cert: temp_variant_cache){
                        possible_certificates.push_back(boost::get<CertificateV3>(cert));
                    }
                    possible_certificates_from_cache = true;
                }
                break;
            }
            case SignerInfoType::Certificate_Chain: {
                chain = boost::get<std::list<CertificateVariant>>(*signer_info);
                if (chain.empty()) {
                    confirm.report = VerificationReport::Signer_Certificate_Not_Found;
                    return confirm;

                } else if (chain.size() > 3) {
                    // prevent DoS by sending very long chains, maximum length is three certificates, because:
                    // AT → AA → Root and no other signatures are allowed, sending the Root is optional
                    confirm.report = VerificationReport::Invalid_Certificate;
                    return confirm;

                } else if (sign_policy && chain.size() == 1 &&
                           confirm.its_aid == aid::CA && cert_cache &&
                           cert_cache->lookup(signer_hash).empty()) {
                    // Previously unknown certificate, send own certificate in next CAM
                    // See TS 103 097 v1.2.1, section 7.1, 1st bullet, 3rd dash
                    sign_policy->request_certificate();

                } else if (certs && cert_cache && chain.size() > 1) {
                    // pre-check chain certificates, otherwise they're not available for the ticket check
                    // The second certificate will always have to be the AA
                    std::list<CertificateVariant>::iterator it = chain.begin();
                    std::advance(it, 1);
                    CertificateVariant& cert = *it;
                    CertificateValidity validity = certs->check_certificate(cert);

                    // we can abort early if there are invalid AA certificates in the chain
                    if (!validity) {
                        confirm.report = VerificationReport::Invalid_Certificate;
                        confirm.certificate_validity = validity;
                        return confirm;
                    }

                    // We won't cache outdated or premature certificates in the cache and abort early.
                    // This check isn't required as it would just fail below or in the consistency checks,
                    // but it's an optimization and saves us from polluting the cache with such certificates.
                    if (!check_certificate_time(cert, rt.now()) ||
                        (positioning && !check_certificate_region(cert, positioning->position_fix()))
                    ) {
                        confirm.report = VerificationReport::Invalid_Certificate;
                        return confirm;
                    }

                    cert_cache->insert(cert);
                }
                // first certificate must be the authorization ticket
                signer_hash =  calculate_hash(chain.front());
                possible_certificates.push_back(chain.front());
                break;
            }
            default: {
                confirm.report = VerificationReport::Unsupported_Signer_Identifier_Type;
                return confirm;
            }
        }
    }
    if (possible_certificates.size() == 0) {
        confirm.report = VerificationReport::Signer_Certificate_Not_Found;
        confirm.certificate_id = signer_hash;
        if (sign_policy) {
            sign_policy->request_unrecognized_certificate(signer_hash);
        }
        return confirm;
    }
    if (!check_generation_time(secured_message, rt.now())) {
        confirm.report = VerificationReport::Invalid_Timestamp;
        return confirm;
    }
    // TODO check Duplicate_Message, Invalid_Mobility_Data, Unencrypted_Message, Decryption_Error

    // check signature
    const boost::optional<security::Signature> signature_variant = secured_message.get_signature();
    if (!signature_variant) {
        confirm.report = VerificationReport::Unsigned_Message;
        return confirm;
    }

    const boost::optional<EcdsaSignature> signature = extract_ecdsa_signature(*signature_variant);
    if (!signature) {
        confirm.report = VerificationReport::False_Signature;
        return confirm;
    }
    // verify payload signature with given signature
    ByteBuffer payload = secured_message.convert_for_signing();
    boost::optional<CertificateVariant> signer;

    for (const auto& cert : possible_certificates) {
        // The Subject type disappears on the V1.3.1
        const CertificateV3& certificateV3 = boost::get<CertificateV3>(cert);
        boost::optional<ecdsa256::PublicKey> public_key = certificateV3.get_public_key(backend);
        boost::optional<std::string> curve_name = certificateV3.get_public_key_curve_name();

        if (!public_key || !curve_name) {
            confirm.report = VerificationReport::Invalid_Certificate;
            confirm.certificate_validity = CertificateInvalidReason::Missing_Public_Key;
            return confirm;
        }

        ByteBuffer signature_input = calculate_sha_signature_inputV3(payload, certificateV3, *curve_name);
        if (backend.verify_data(*public_key, signature_input, *signature, *curve_name)) {
            signer = cert;
            break;
        }
    }

    if (!signer) {
        // HashedId8 of authorization tickets is not guaranteed to be globally unique.
        // The collision probability is rather low, but it might happen.
        if (signer_info && get_type(*signer_info) == SignerInfoType::Certificate_Digest_With_SHA256) {
            // assume a hash collision since we got only a digest with message
            confirm.report = VerificationReport::Signer_Certificate_Not_Found;
        } else {
            // signature does not match the certificate received with this message
            confirm.report = VerificationReport::False_Signature;
        }

        confirm.certificate_id = signer_hash;
        if (sign_policy) {
            sign_policy->request_unrecognized_certificate(signer_hash);
        }
        return confirm;
    }

    // we can only check the generation location after we have identified the correct certificate
    // ignore for certificate management messages
    if (its_aid != aid::SCR && its_aid != aid::CTL && its_aid != aid::CRL && !check_generation_location(secured_message, *signer)) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Off_Region;
        return confirm;
    }

    CertificateValidity cert_validity = CertificateValidity::valid();
    if (certs && !possible_certificates_from_cache) { // certificates from cache are already verified as trusted
        cert_validity = certs->check_certificate(*signer);
    }

    confirm.certificate_validity = cert_validity;

    // if certificate could not be verified return correct DecapReport
    if (!cert_validity) {
        confirm.report = VerificationReport::Invalid_Certificate;

        if (cert_validity.reason() == CertificateInvalidReason::Unknown_Signer && secured_message.is_signer_digest()) {
            confirm.certificate_id = signer_hash;
            if (sign_policy) {
                sign_policy->request_unrecognized_certificate(signer_hash);
            }
        }

        return confirm;
    }

    if (!check_certificate_time(*signer, rt.now())) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Off_Time_Period;
        return confirm;
    }

    if (positioning && !check_certificate_region(*signer, positioning->position_fix())) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Off_Region;
        return confirm;
    }

    // Assign permissions from the certificate based on the message AID already present in the confirm
    // and reject the certificate if no permissions are present for the claimed AID.
    if (!assign_permissions(*signer, confirm)) {
        // This might seem weird, because the certificate itself is valid, but not for the received message.
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Insufficient_ITS_AID;
        return confirm;
    }

    // cache only certificates that are useful, one that mismatches its restrictions isn't
    if (cert_cache) {
        cert_cache->insert(*signer);
    }

    confirm.report = VerificationReport::Success;
    return confirm;
}

VerifyConfirm verify_v2(VerifyRequest& request, const Runtime& rt, CertificateProvider& cert_provider, CertificateValidator& certs, Backend& backend, CertificateCache& cert_cache, SignHeaderPolicy& sign_policy, PositionProvider& positioning){
    VerifyConfirm confirm;
    const SecuredMessageV2 secured_message = boost::get<SecuredMessageV2>(request.secured_message);

    if (cert_provider.version() != 2){
        confirm.report = VerificationReport::Incompatible_Protocol;
        return confirm;
    }

    if (PayloadType::Signed != secured_message.payload.type) {
        confirm.report = VerificationReport::Unsigned_Message;
        return confirm;
    }

    if (2 != secured_message.protocol_version()) {
        confirm.report = VerificationReport::Incompatible_Protocol;
        return confirm;
    }

    const std::list<HashedId3>* requested_certs = secured_message.header_field<HeaderFieldType::Request_Unrecognized_Certificate>();
    if (requested_certs) {
        for (auto& requested_cert : *requested_certs) {
            if (truncate(calculate_hash(boost::get<Certificate>(cert_provider.own_certificate()))) == requested_cert) {
                sign_policy.request_certificate();
            }

            for (auto& cert : cert_provider.own_chain()) {
                if (truncate(calculate_hash(boost::get<Certificate>(cert))) == requested_cert) {
                    sign_policy.request_certificate_chain();
                }
            }
        }
    }

    const IntX* its_aid = secured_message.header_field<HeaderFieldType::Its_Aid>();
    if (!its_aid) {
        // ITS-AID is required to be present, report as incompatible protocol, as that's the closest match
        confirm.report = VerificationReport::Incompatible_Protocol;
        return confirm;
    }
    confirm.its_aid = its_aid->get();

    const SignerInfo* signer_info = secured_message.header_field<HeaderFieldType::Signer_Info>();
    std::list<CertificateVariant> possible_certificates;
    bool possible_certificates_from_cache = false;

    // use a dummy hash for initialization
    HashedId8 signer_hash;
    signer_hash.fill(0x00);

    std::list<CertificateVariant> temp_variant_cache;


    if (signer_info) {
        switch (get_type(*signer_info)) {
            case SignerInfoType::Certificate:
                possible_certificates.push_back(boost::get<CertificateVariant>(*signer_info));
                signer_hash = calculate_hash(boost::get<CertificateVariant>(*signer_info));

                if (confirm.its_aid == aid::CA && cert_cache.lookup(signer_hash, SubjectType::Authorization_Ticket).size() == 0) {
                    // Previously unknown certificate, send own certificate in next CAM
                    // See TS 103 097 v1.2.1, section 7.1, 1st bullet, 3rd dash
                    sign_policy.request_certificate();
                }

                break;
            case SignerInfoType::Certificate_Digest_With_SHA256:
                signer_hash = boost::get<HashedId8>(*signer_info);
                temp_variant_cache = cert_cache.lookup(signer_hash);
                for (const auto& cert: temp_variant_cache){
                    possible_certificates.push_back(boost::get<Certificate>(cert));
                }
                //possible_certificates.splice(possible_certificates.end(), cert_cache.lookup(signer_hash, SubjectType::Authorization_Ticket));
                possible_certificates_from_cache = true;
                break;
            case SignerInfoType::Certificate_Chain:
            {
                std::list<CertificateVariant> chain = boost::get<std::list<CertificateVariant>>(*signer_info);
                if (chain.size() == 0) {
                    confirm.report = VerificationReport::Signer_Certificate_Not_Found;
                    return confirm;
                } else if (chain.size() > 3) {
                    // prevent DoS by sending very long chains, maximum length is three certificates, because:
                    // AT → AA → Root and no other signatures are allowed, sending the Root is optional
                    confirm.report = VerificationReport::Invalid_Certificate;
                    return confirm;
                }
                // pre-check chain certificates, otherwise they're not available for the ticket check
                for (auto& cert_temp : chain) {
                    // root certificates must already be known, otherwise the validation will fail anyway
                    if (CertificateVariantVersion(cert_temp.which()) == CertificateVariantVersion::Two){
                        const Certificate& cert = boost::get<Certificate>(cert_temp);
                        if (cert.subject_info.subject_type == SubjectType::Authorization_Authority) {
                            // there's no need to report unknown signers at this point, see comment above
                            CertificateValidity validity = certs.check_certificate(cert);

                            // we can abort early if there are invalid AA certificates in the chain
                            if (!validity) {
                                confirm.report = VerificationReport::Invalid_Certificate;
                                confirm.certificate_validity = validity;
                                return confirm;
                            }

                            // We won't cache outdated or premature certificates in the cache and abort early.
                            // This check isn't required as it would just fail below or in the consistency checks,
                            // but it's an optimization and saves us from polluting the cache with such certificates.
                            if (!check_certificate_time(cert, rt.now()) || !check_certificate_region(cert, positioning.position_fix())) {
                                confirm.report = VerificationReport::Invalid_Certificate;
                                return confirm;
                            }

                            cert_cache.insert(cert);
                        }
                    }
                }
                // last certificate must be the authorization ticket
                signer_hash = calculate_hash(chain.back());
                possible_certificates.push_back(chain.back());
            }
                break;
            default:
                confirm.report = VerificationReport::Unsupported_Signer_Identifier_Type;
                return confirm;
                break;
        }
    }

    if (possible_certificates.size() == 0) {
        confirm.report = VerificationReport::Signer_Certificate_Not_Found;
        confirm.certificate_id = signer_hash;
        sign_policy.request_unrecognized_certificate(signer_hash);
        return confirm;
    }

    if (!check_generation_time(secured_message, rt.now())) {
        confirm.report = VerificationReport::Invalid_Timestamp;
        return confirm;
    }

    // TODO check Duplicate_Message, Invalid_Mobility_Data, Unencrypted_Message, Decryption_Error

    // check signature
    const TrailerField* signature_field = secured_message.trailer_field(TrailerFieldType::Signature);
    const Signature* signature = boost::get<Signature>(signature_field);

    if (!signature) {
        confirm.report = VerificationReport::Unsigned_Message;
        return confirm;
    }

    if (PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256 != get_type(*signature)) {
        confirm.report = VerificationReport::False_Signature;
        return confirm;
    }

    // check the size of signature.R and siganture.s
    auto ecdsa = extract_ecdsa_signature(*signature);
    const auto field_len = field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);
    if (!ecdsa || ecdsa->s.size() != field_len) {
        confirm.report = VerificationReport::False_Signature;
        return confirm;
    }

    // verify payload signature with given signature
    ByteBuffer payload = convert_for_signing(secured_message, secured_message.trailer_fields);
    boost::optional<Certificate> signer;

    for (const auto& cert_temp : possible_certificates) {
        const Certificate& cert = boost::get<Certificate>(cert_temp);
        SubjectType subject_type = cert.subject_info.subject_type;
        if (subject_type != SubjectType::Authorization_Ticket) {
            confirm.report = VerificationReport::Invalid_Certificate;
            confirm.certificate_validity = CertificateInvalidReason::Invalid_Signer;
            return confirm;
        }

        boost::optional<ecdsa256::PublicKey> public_key = get_public_key(cert, backend);

        // public key could not be extracted
        if (!public_key) {
            confirm.report = VerificationReport::Invalid_Certificate;
            confirm.certificate_validity = CertificateInvalidReason::Missing_Public_Key;
            return confirm;
        }

        if (backend.verify_data(public_key.get(), payload, *ecdsa)) {
            signer = cert;
            break;
        }
    }

    if (!signer) {
        // HashedId8 of authorization tickets is not guaranteed to be globally unique.
        // The collision probability is rather low, but it might happen.
        if (signer_info && get_type(*signer_info) == SignerInfoType::Certificate_Digest_With_SHA256) {
            // assume a hash collision since we got only a digest with message
            confirm.report = VerificationReport::Signer_Certificate_Not_Found;
        } else {
            // signature does not match the certificate received with this message
            confirm.report = VerificationReport::False_Signature;
        }

        confirm.certificate_id = signer_hash;
        sign_policy.request_unrecognized_certificate(signer_hash);
        return confirm;
    }

    // we can only check the generation location after we have identified the correct certificate
    if (!check_generation_location(secured_message, *signer)) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Off_Region;
        return confirm;
    }

    CertificateValidity cert_validity = CertificateValidity::valid();
    if (!possible_certificates_from_cache) { // certificates from cache are already verified as trusted
        cert_validity = certs.check_certificate(*signer);
    }

    confirm.certificate_validity = cert_validity;

    // if certificate could not be verified return correct DecapReport
    if (!cert_validity) {
        confirm.report = VerificationReport::Invalid_Certificate;

        if (cert_validity.reason() == CertificateInvalidReason::Unknown_Signer) {
            if (get_type(signer->signer_info) == SignerInfoType::Certificate_Digest_With_SHA256) {
                auto signer_hash = boost::get<HashedId8>(signer->signer_info);
                confirm.certificate_id = signer_hash;
                sign_policy.request_unrecognized_certificate(signer_hash);
            }
        }

        return confirm;
    }

    if (!check_certificate_time(*signer, rt.now())) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Off_Time_Period;
        return confirm;
    }

    if (!check_certificate_region(*signer, positioning.position_fix())) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Off_Region;
        return confirm;
    }

    // Assign permissions from the certificate based on the message AID already present in the confirm
    // and reject the certificate if no permissions are present for the claimed AID.
    if (!assign_permissions(*signer, confirm)) {
        // This might seem weird, because the certificate itself is valid, but not for the received message.
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Insufficient_ITS_AID;
        return confirm;
    }

    // cache only certificates that are useful, one that mismatches its restrictions isn't
    cert_cache.insert(*signer);

    confirm.report = VerificationReport::Success;
    return confirm;
}

VerifyService straight_verify_service(const Runtime& rt, CertificateProvider& cert_provider, CertificateValidator& certs, Backend& backend, CertificateCache& cert_cache, SignHeaderPolicy& sign_policy, PositionProvider& positioning)
{
    return [&](VerifyRequest&& request) -> VerifyConfirm {
        // TODO check if certificates in chain have been revoked for all CA certificates, ATs are never revoked

        VerifyConfirm confirm;
        class version_visitor : public boost::static_visitor<int>
        {
        public:
            int operator()(const SecuredMessage& message) const
            {
                return 2;
            }

            int operator()(const SecuredMessageV3& message) const
            {
                return 3;
            }
        };
        int version = boost::apply_visitor(version_visitor(), request.secured_message);
        if (version == 2){
            confirm = verify_v2(request, rt, cert_provider, certs, backend, cert_cache, sign_policy, positioning);
        }else if(version == 3){
            confirm = verify_v3(request, rt, cert_provider, certs, backend, cert_cache, sign_policy, positioning);
        }else{
            confirm.report = VerificationReport::Incompatible_Protocol;
        }
        return confirm;
    };
}

VerifyService dummy_verify_service(VerificationReport report, CertificateValidity validity)
{
    return [=](VerifyRequest&& request) -> VerifyConfirm {
        VerifyConfirm confirm;
        confirm.report = report;
        confirm.certificate_validity = validity;
        class int_x_visitor : public boost::static_visitor<const IntX*>
        {
        public:
            const IntX* operator()(const SecuredMessageV2& message) const
            {
                return message.header_field<HeaderFieldType::Its_Aid>();
            }

            const IntX* operator()(const SecuredMessageV3& message) const
            {
                return new IntX(message.get_psid());
            }
        };
        const IntX* its_aid = boost::apply_visitor(int_x_visitor(), request.secured_message);
        confirm.its_aid = its_aid ? its_aid->get() : 0;
        return confirm;
    };
}


} // namespace security
} // namespace vanetza
