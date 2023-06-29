#include <iostream>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/self_certificate_provider.hpp>
#include <vanetza/security/sign_header_policy.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/encrypt_service.hpp>
#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/pki/enrolment_certificates.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/net/packet.hpp>
#include <vanetza/asn1/etsi_ts_102_941_data.hpp>


namespace vanetza {

namespace pki {

security::EncryptConfirm
build_enrolment_request(const std::string &its_id,
                       const security::openssl::EvpKey &verification_key,
                       security::CertificateProvider& active_certificate_provider,
                       const security::CertificateV3& target_certificate,
                       const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list)
{
    // Build inner EC request with itsId, verificationKey and subject attributes
    asn1::InnerEcRequest inner_ec_request = build_inner_ec_request(its_id, verification_key, psid_ssp_list);
    auto tmp = inner_ec_request.encode();

    // Sign inner EC request with verification key for proof of possession
    security::SecuredMessageV3 inner_ec_request_signed_for_pop_message =
        sign_inner_ec_request(std::move(inner_ec_request), verification_key);
    ByteBuffer inner_ec_request_signed_for_pop_bb = inner_ec_request_signed_for_pop_message.serialize();
    // Decode into a temporary object
    InnerEcRequestSignedForPop_t *tmp_inner_ec_request_signed_for_pop = nullptr;
    asn1::decode_oer(asn_DEF_InnerEcRequestSignedForPop,
                     (void **)&tmp_inner_ec_request_signed_for_pop,
                     inner_ec_request_signed_for_pop_bb);

    // Wrap signed inner EC request into EtsiTs102941Data
    asn1::EtsiTs102941Data signed_inner_ec_request_wrap;
    signed_inner_ec_request_wrap->version = Version_v1;

    EtsiTs102941DataContent_t &content = signed_inner_ec_request_wrap->content;
    CHOICE_variant_set_presence(&asn_DEF_EtsiTs102941DataContent, &content,
                                EtsiTs102941DataContent_PR_enrolmentRequest);

    // Swap temporary object into the choice
    InnerEcRequestSignedForPop_t &inner_ec_request_signed_for_pop = content.choice.enrolmentRequest;
    std::swap(inner_ec_request_signed_for_pop, *tmp_inner_ec_request_signed_for_pop);
    asn1::free(asn_DEF_InnerEcRequestSignedForPop, tmp_inner_ec_request_signed_for_pop);
    ByteBuffer signed_inner_ec_request_wrap_bb = signed_inner_ec_request_wrap.encode();

    // Final signature with currently active certificate
    security::SecuredMessageV3 signed_outer_ec_request_message =
        sign_ec_request_data(std::move(signed_inner_ec_request_wrap),
                             active_certificate_provider,
                             security::PayloadTypeV3::RawUnsecured);
    ByteBuffer tmp_outer = signed_outer_ec_request_message.serialize();
    asn1::EtsiTs103097Data signed_outer_ec_request;
    signed_outer_ec_request.decode(tmp_outer);

    // Encryption
    security::EncryptConfirm encrypted_ec_request =
        encrypt_ec_request(std::move(signed_outer_ec_request), target_certificate);

    return encrypted_ec_request;
}

security::EncryptConfirm
build_enrolment_request(const std::string &its_id,
                       const security::openssl::EvpKey &verification_key,
                       const security::openssl::EvpKey &canonical_key,
                       const security::CertificateV3 &target_certificate,
                       const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list)
{
    security::SelfCertificateProvider canonical_key_provider(canonical_key.private_key());
    return build_enrolment_request(its_id, verification_key, canonical_key_provider, target_certificate, psid_ssp_list);
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
    asn1::PublicVerificationKey public_verification_key = verification_key.public_verification_key();
    std::swap(inner_ec_request->publicKeys.verificationKey, *public_verification_key);
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
                     security::CertificateProvider &certificate_provider,
                     security::PayloadTypeV3 request_data_type)
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
    sign_request.message_type = request_data_type;

    security::SignConfirm sign_confirm = sign_service(std::move(sign_request));
    return boost::get<security::SecuredMessageV3>(sign_confirm.secured_message);
}

security::SecuredMessageV3
sign_inner_ec_request(asn1::InnerEcRequest &&inner_ec_request,
                      const security::openssl::EvpKey &verification_key)
{
    security::SelfCertificateProvider verification_key_provider(verification_key.private_key());
    return sign_ec_request_data(std::move(inner_ec_request),
                                verification_key_provider,
                                security::PayloadTypeV3::RawUnsecured);
}

security::EncryptConfirm
encrypt_ec_request(asn1::EtsiTs103097Data &&ec_request, const security::CertificateV3 &target_certificate)
{
    security::BackendOpenSsl backend;

    DownPacket packet;
    packet.layer(OsiLayer::Application) = std::move(ec_request);

    security::EncryptService encrypt_service = security::straight_encrypt_serviceV3(backend);
    security::EncryptRequest encrypt_request { std::move(packet), target_certificate };

    security::EncryptConfirm encrypt_confirm = encrypt_service(encrypt_request);
    return encrypt_confirm;
}

} // namespace pki

} // namespace vanetza
