#include <iostream>

#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/pki/enrolment_certificates.hpp>
#include <vanetza/common/its_aid.hpp>


namespace vanetza {

namespace pki {

asn1::InnerEcRequest
build_inner_ec_request(const std::string &its_id,
                       const security::openssl::EvpKey &verification_key,
                       const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list)
{
    asn1::InnerEcRequest inner_ec_request;
    inner_ec_request->certificateFormat = CertificateFormat_ts103097v131;
    OCTET_STRING_fromString(&inner_ec_request->itsId, its_id.data());
    set_public_verification_key(inner_ec_request, verification_key);
    set_certificate_subject_attributes(inner_ec_request, its_id);
    if (psid_ssp_list) set_psid_ssps(inner_ec_request, *psid_ssp_list);

    return inner_ec_request;
}

void set_public_verification_key(asn1::InnerEcRequest& inner_ec_request, const security::openssl::EvpKey& verification_key)
{
    security::ecdsa256::PublicKey public_key = verification_key.public_key();
    std::string group_name = verification_key.group_name();

    if (group_name == "prime256v1") {
        inner_ec_request->publicKeys.verificationKey.present = PublicVerificationKey_PR_ecdsaNistP256;
        inner_ec_request->publicKeys.verificationKey.choice.ecdsaNistP256.present = EccP256CurvePoint_PR_uncompressedP256;
        OCTET_STRING_fromBuf(
            &inner_ec_request->publicKeys.verificationKey.choice.ecdsaNistP256
                 .choice.uncompressedP256.x,
            reinterpret_cast<const char*>(public_key.x.data()), public_key.x.size());
        OCTET_STRING_fromBuf(
            &inner_ec_request->publicKeys.verificationKey.choice.ecdsaNistP256
                 .choice.uncompressedP256.y,
            reinterpret_cast<const char*>(public_key.y.data()), public_key.y.size());
    } else if (group_name == "brainpoolP256r1") {
        inner_ec_request->publicKeys.verificationKey.present = PublicVerificationKey_PR_ecdsaBrainpoolP256r1;
        inner_ec_request->publicKeys.verificationKey.choice.ecdsaBrainpoolP256r1.present = EccP256CurvePoint_PR_uncompressedP256;
        OCTET_STRING_fromBuf(
            &inner_ec_request->publicKeys.verificationKey.choice.ecdsaBrainpoolP256r1
                 .choice.uncompressedP256.x,
            reinterpret_cast<const char*>(public_key.x.data()), public_key.x.size());
        OCTET_STRING_fromBuf(
            &inner_ec_request->publicKeys.verificationKey.choice.ecdsaBrainpoolP256r1
                 .choice.uncompressedP256.y,
            reinterpret_cast<const char*>(public_key.y.data()), public_key.y.size());
    } else {
        throw std::domain_error("Unsupported EC group");
    }
}

void set_certificate_subject_attributes(asn1::InnerEcRequest& inner_ec_request, const std::string& its_id)
{
    // id is optional, we need to initialize it first
    inner_ec_request->requestedSubjectAttributes.id = asn1::allocate<CertificateId_t>();
    inner_ec_request->requestedSubjectAttributes.id->present = CertificateId_PR_name;
    OCTET_STRING_fromString(&inner_ec_request->requestedSubjectAttributes.id->choice.name, its_id.data());
}

void set_psid_ssps(asn1::InnerEcRequest& inner_ec_request, const asn1::SequenceOfPsidSsp& psid_ssp_list)
{
    auto *psid_ssp_list_copy = static_cast<SequenceOfPsidSsp_t *>(
        asn1::copy(asn_DEF_SequenceOfPsidSsp, &(*psid_ssp_list)));
    inner_ec_request->requestedSubjectAttributes.appPermissions = psid_ssp_list_copy;
}

} // namespace pki

} // namespace vanetza
