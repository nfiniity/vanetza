#include <iostream>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/self_certificate_provider.hpp>
#include <vanetza/security/sign_header_policy.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/pki/enrolment_certificates.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/net/packet.hpp>


namespace vanetza {

namespace pki {

security::SecuredMessageV3
build_enrolment_request(const std::string &its_id,
                       const security::openssl::EvpKey &verification_key,
                       security::CertificateProvider& active_certificate_provider,
                       const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list)
{
    asn1::InnerEcRequest inner_ec_request = build_inner_ec_request(its_id, verification_key, psid_ssp_list);

    security::SecuredMessageV3 signed_inner_ec_request_message = sign_inner_ec_request(std::move(inner_ec_request), verification_key);
    ByteBuffer tmp_inner = signed_inner_ec_request_message.serialize();
    asn1::EtsiTs103097Data signed_inner_ec_request;
    signed_inner_ec_request.decode(tmp_inner);

    security::SecuredMessageV3 signed_outer_ec_request_message = sign_ec_request_data(std::move(signed_inner_ec_request), active_certificate_provider);
    ByteBuffer tmp_outer = signed_outer_ec_request_message.serialize();
    asn1::EtsiTs103097Data signed_outer_ec_request;
    signed_outer_ec_request.decode(tmp_outer);

    return signed_outer_ec_request_message;
}

security::SecuredMessageV3
build_enrolment_request(const std::string &its_id,
                       const security::openssl::EvpKey &verification_key,
                       const security::openssl::EvpKey &canonical_key,
                       const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list)
{
    security::SelfCertificateProvider canonical_key_provider(canonical_key.private_key());
    return build_enrolment_request(its_id, verification_key, canonical_key_provider, psid_ssp_list);
}

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

// Common method to sign both the inner and outer data structures
security::SecuredMessageV3
sign_ec_request_data(ByteBufferConvertible &&request_data,
                     security::CertificateProvider &certificate_provider)
{
    std::unique_ptr<security::Backend> backend(security::create_backend("default"));
    // Position is not used for signing here, so we can use a dummy provider
    StoredPositionProvider position_provider;
    ManualRuntime runtime(Clock::at(boost::posix_time::microsec_clock::universal_time()));
    security::DefaultSignHeaderPolicy sign_header_policy(runtime, position_provider);

    security::SignService sign_service(security::straight_sign_serviceV3(certificate_provider, *backend, sign_header_policy));
    security::SignRequest sign_request;
    sign_request.its_aid = aid::SCR;

    DownPacket packet;
    packet.layer(OsiLayer::Application) = std::move(request_data);
    sign_request.plain_message = std::move(packet);

    security::SignConfirm sign_confirm = sign_service(std::move(sign_request));
    return boost::get<security::SecuredMessageV3>(sign_confirm.secured_message);
}

security::SecuredMessageV3
sign_inner_ec_request(asn1::InnerEcRequest &&inner_ec_request,
                      const security::openssl::EvpKey &verification_key)
{
    security::SelfCertificateProvider verification_key_provider(verification_key.private_key());
    return sign_ec_request_data(std::move(inner_ec_request), verification_key_provider);
}

} // namespace pki

} // namespace vanetza
