#include <iostream>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/self_certificate_provider.hpp>
#include <vanetza/security/sign_header_policy.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/encrypt_service.hpp>
#include <vanetza/security/decrypt_service.hpp>
#include <vanetza/security/verify_service.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/security/trust_store.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/pki/enrolment_certificates.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/net/packet.hpp>
#include <vanetza/asn1/etsi_ts_102_941_data.hpp>


namespace vanetza {

namespace pki {

security::EncryptConfirm
build_enrolment_request(const ByteBuffer &its_id,
                        const security::openssl::EvpKey &verification_key,
                        security::CertificateProvider& active_certificate_provider,
                        const security::CertificateV3& ea_certificate,
                        const Runtime &runtime,
                        const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list,
                        const std::string& verification_key_curve_name)
{
    // Build inner EC request with itsId, verificationKey and subject attributes
    asn1::InnerEcRequest inner_ec_request = build_inner_ec_request(its_id, verification_key, psid_ssp_list);
    auto tmp = inner_ec_request.encode();

    // Sign inner EC request with verification key for proof of possession
    security::SelfCertificateProvider verification_certificate_provider(verification_key.private_key(), verification_key_curve_name);
    security::SecuredMessageV3 inner_ec_request_signed_for_pop_message =
        sign_ec_request_data(std::move(inner_ec_request),
                             verification_certificate_provider,
                             security::PayloadTypeV3::RawUnsecured,
                             runtime);
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
                             security::PayloadTypeV3::RawUnsecured,
                             runtime);
    ByteBuffer tmp_outer = signed_outer_ec_request_message.serialize();
    asn1::EtsiTs103097Data signed_outer_ec_request;
    signed_outer_ec_request.decode(tmp_outer);

    // Encryption
    security::EncryptConfirm encrypted_ec_request =
        encrypt_ec_request(std::move(signed_outer_ec_request), ea_certificate);

    return encrypted_ec_request;
}

asn1::InnerEcRequest
build_inner_ec_request(const ByteBuffer &its_id,
                       const security::openssl::EvpKey &verification_key,
                       const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list)
{
    asn1::InnerEcRequest inner_ec_request;
    inner_ec_request->certificateFormat = CertificateFormat_ts103097v131;
    OCTET_STRING_fromBuf(&inner_ec_request->itsId,
                         reinterpret_cast<const char *>(its_id.data()),
                         its_id.size());
    set_public_verification_key(inner_ec_request, verification_key);
    if (psid_ssp_list) set_psid_ssps(inner_ec_request, *psid_ssp_list);

    return inner_ec_request;
}

void set_public_verification_key(asn1::InnerEcRequest& inner_ec_request, const security::openssl::EvpKey& verification_key)
{
    asn1::PublicVerificationKey public_verification_key = verification_key.public_verification_key();
    std::swap(inner_ec_request->publicKeys.verificationKey, *public_verification_key);
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
                     security::PayloadTypeV3 request_data_type,
                     const Runtime &runtime)
{
    std::unique_ptr<security::Backend> backend(security::create_backend("default"));
    // Position is not used for signing here, so we can use a dummy provider
    StoredPositionProvider position_provider;
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

security::EncryptConfirm
encrypt_ec_request(asn1::EtsiTs103097Data &&ec_request, const security::CertificateV3 &ea_certificate)
{
    security::BackendOpenSsl backend;

    DownPacket packet;
    packet.layer(OsiLayer::Application) = std::move(ec_request);

    security::EncryptService encrypt_service = security::straight_encrypt_serviceV3(backend);
    security::EncryptRequest encrypt_request { std::move(packet), ea_certificate };

    security::EncryptConfirm encrypt_confirm = encrypt_service(encrypt_request);
    return encrypt_confirm;
}

security::CertificateV3
decode_ec_response(const security::SecuredMessageV3 &ec_response,
                   const std::array<uint8_t, 16> &session_key,
                   const security::CertificateV3 &ea_certificate,
                   const Runtime &runtime)
{
    // Decrypt the response
    assert(ec_response.is_encrypted_message());
    security::BackendOpenSsl backend;
    security::DecryptService decrypt_service = security::straight_decrypt_serviceV3(backend);
    security::DecryptRequest decrypt_request { ec_response, session_key };
    security::DecryptConfirm decrypt_response = decrypt_service(decrypt_request);

    security::CertificateCache cert_cache(runtime);
    cert_cache.insert_v3(ea_certificate);

    security::SecuredMessageVariant sec_packet = decrypt_response.decrypted_message;
    security::VerifyRequest verify_request(sec_packet);

    auto verify_res = security::verify_v3(verify_request, runtime, boost::none, boost::none,
                                          backend, cert_cache, boost::none, boost::none);
    assert(verify_res.report == vanetza::security::VerificationReport::Success);

    // Decode the EtsiTs102941Data structure
    const vanetza::ByteBuffer etsi_ts_102_941_data_bb = decrypt_response.decrypted_message.get_payload();
    vanetza::asn1::EtsiTs102941Data etsi_ts_102_941_data;
    etsi_ts_102_941_data.decode(etsi_ts_102_941_data_bb);
    // Check for correct reponse type
    assert(etsi_ts_102_941_data->content.present == EtsiTs102941DataContent_PR_enrolmentResponse);

    const InnerEcResponse_t &ec_enrolment_response = etsi_ts_102_941_data->content.choice.enrolmentResponse;
    // Check for successful response
    assert(ec_enrolment_response.responseCode == EnrolmentResponseCode_ok);

    // Copy the certificate into the return value
    const vanetza::ByteBuffer ec_bb = vanetza::asn1::encode_oer(
        asn_DEF_EtsiTs103097Certificate, ec_enrolment_response.certificate);
    return security::CertificateV3(ec_bb);
}

} // namespace pki

} // namespace vanetza
