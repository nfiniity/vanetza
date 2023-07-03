#include <boost/date_time/posix_time/posix_time.hpp>
#include <iostream>

#include <vanetza/asn1/etsi_ts_102_941_data.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/net/packet.hpp>
#include <vanetza/pki/authorization_tickets.hpp>
#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/security/encrypt_service.hpp>
#include <vanetza/security/decrypt_service.hpp>
#include <vanetza/security/sign_header_policy.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/self_certificate_provider.hpp>

namespace vanetza {

namespace pki {

security::EncryptConfirm
build_at_request(const security::openssl::EvpKey &at_verification_key,
                 security::CertificateProvider &ec_provider,
                 const security::CertificateV3 &ea_certificate,
                 const security::CertificateV3 &aa_certificate,
                 const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list,
                 const std::string &at_verification_key_curve_name)
{
    security::BackendOpenSsl backend;

    // Generate HMAC over the verification key
    ByteBuffer hmac_key = backend.random_bytes(32);
    asn1::PublicVerificationKey at_public_verification_key_asn1 =
        at_verification_key.public_verification_key();
    std::array<uint8_t, 16> key_tag =
        backend.hmac_sha256(hmac_key, at_public_verification_key_asn1.encode());

    asn1::SharedAtRequest shared_at_request =
        build_shared_at_request(ec_provider, key_tag, psid_ssp_list);

    asn1::EcSignature ec_signature = build_ec_signature(
        shared_at_request, ec_provider, ea_certificate, backend);

    asn1::EtsiTs102941Data inner_at_request_wrapped =
        build_inner_at_request_wrapped(ec_signature, shared_at_request,
                                       at_public_verification_key_asn1,
                                       hmac_key);

    security::SelfCertificateProvider at_verficiation_key_provider(at_verification_key.private_key(), at_verification_key_curve_name);
    return sign_and_encrypt_inner_at_request_wrapped(
        inner_at_request_wrapped, at_verficiation_key_provider, aa_certificate, backend);
}

asn1::SharedAtRequest
build_shared_at_request(security::CertificateProvider &ec_provider,
                        const std::array<uint8_t, 16> &key_tag,
                        const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list)
{
    asn1::SharedAtRequest shared_at_request;
    shared_at_request->certificateFormat = CertificateFormat_ts103097v131;

    OCTET_STRING_fromBuf(&shared_at_request->keyTag, reinterpret_cast<const char*>(key_tag.data()), key_tag.size());

    // Copy the eaId from the enrolment certificate into shared_at_request
    const security::CertificateV3 &ec = boost::get<security::CertificateV3>(ec_provider.own_certificate());
    const security::HashedId8 ea_id = ec.get_issuer_identifier();
    OCTET_STRING_fromBuf(&shared_at_request->eaId, reinterpret_cast<const char*>(ea_id.data()), ea_id.size());

    if (psid_ssp_list) set_psid_ssps(shared_at_request, *psid_ssp_list);

    return shared_at_request;
}

void set_psid_ssps(asn1::SharedAtRequest& shared_at_request, const asn1::SequenceOfPsidSsp& psid_ssp_list)
{
    auto *psid_ssp_list_copy = static_cast<SequenceOfPsidSsp_t *>(
        asn1::copy(asn_DEF_SequenceOfPsidSsp, &(*psid_ssp_list)));
    shared_at_request->requestedSubjectAttributes.appPermissions = psid_ssp_list_copy;
}

asn1::EcSignature
build_ec_signature(asn1::SharedAtRequest shared_at_request,
                   security::CertificateProvider &ec_provider,
                   const security::CertificateV3 &ea_certificate,
                   security::BackendOpenSsl &backend)
{
    // Position is not used for signing here, so we can use a dummy provider
    StoredPositionProvider position_provider;
    ManualRuntime runtime(Clock::at(boost::posix_time::microsec_clock::universal_time()));
    security::DefaultSignHeaderPolicy sign_header_policy(runtime, position_provider);

    // Sign the shared_at_request as external payload with our EC key
    security::SignRequest sign_request;
    sign_request.its_aid = aid::SCR;

    DownPacket packet_shared_at_request;
    packet_shared_at_request.layer(OsiLayer::Application) = std::move(shared_at_request);
    sign_request.plain_message = std::move(packet_shared_at_request);
    sign_request.external_payload = true;

    security::SignService sign_service(security::straight_sign_serviceV3(ec_provider, backend, sign_header_policy));
    security::SignConfirm sign_confirm = sign_service(std::move(sign_request));
    ByteBuffer signed_external_shared_at_request_bb =
        boost::get<security::SecuredMessageV3>(sign_confirm.secured_message).serialize();

    // Encrypt the signed shared_at_request for the EA
    DownPacket packet_signed_external_shared_at_request;
    packet_signed_external_shared_at_request.layer(OsiLayer::Application) =
        std::move(signed_external_shared_at_request_bb);

    security::EncryptService encrypt_service = security::straight_encrypt_serviceV3(backend);
    security::EncryptRequest encrypt_request{
        std::move(packet_signed_external_shared_at_request), ea_certificate};
    security::EncryptConfirm encrypt_confirm = encrypt_service(encrypt_request);

    ByteBuffer encrypted_data_bb = encrypt_confirm.secured_message.serialize();
    asn1::EtsiTs103097Data encrypted_data;
    encrypted_data.decode(encrypted_data_bb);

    asn1::EcSignature ec_signature;
    CHOICE_variant_set_presence(&asn_DEF_EcSignature, &(*ec_signature), EcSignature_PR_encryptedEcSignature);
    std::swap(*encrypted_data, ec_signature->choice.encryptedEcSignature);

    return ec_signature;
}

asn1::EtsiTs102941Data
build_inner_at_request_wrapped(asn1::EcSignature &ec_signature,
                               asn1::SharedAtRequest &shared_at_request,
                               asn1::PublicVerificationKey &at_public_verification_key,
                               const ByteBuffer &hmac_key)
{
    asn1::EtsiTs102941Data inner_at_request_wrapped;
    inner_at_request_wrapped->version = Version_v1;

    EtsiTs102941DataContent_t &content = inner_at_request_wrapped->content;
    CHOICE_variant_set_presence(&asn_DEF_EtsiTs102941DataContent, &content,
                                EtsiTs102941DataContent_PR_authorizationRequest);

    InnerAtRequest_t &inner_at_request = content.choice.authorizationRequest;
    std::swap(*ec_signature, inner_at_request.ecSignature);
    std::swap(*shared_at_request, inner_at_request.sharedAtRequest);
    std::swap(*at_public_verification_key, inner_at_request.publicKeys.verificationKey);
    OCTET_STRING_fromBuf(&inner_at_request.hmacKey,
                         reinterpret_cast<const char *>(hmac_key.data()),
                         hmac_key.size());

    return inner_at_request_wrapped;
}

security::EncryptConfirm
sign_and_encrypt_inner_at_request_wrapped(asn1::EtsiTs102941Data &inner_at_request_wrapped,
                                          security::CertificateProvider &at_verification_key_provider,
                                          const security::CertificateV3 &aa_certificate,
                                          security::BackendOpenSsl &backend)
{
    // Position is not used for signing here, so we can use a dummy provider
    StoredPositionProvider position_provider;
    ManualRuntime runtime(Clock::at(boost::posix_time::microsec_clock::universal_time()));
    security::DefaultSignHeaderPolicy sign_header_policy(runtime, position_provider);

    // Sign the inner_at_request_wrapped with our new AT key
    security::SignRequest sign_request;
    sign_request.its_aid = aid::SCR;

    DownPacket packet_inner_at_request_wrapped;
    packet_inner_at_request_wrapped.layer(OsiLayer::Application) = std::move(inner_at_request_wrapped);
    sign_request.plain_message = std::move(packet_inner_at_request_wrapped);

    security::SignService sign_service = security::straight_sign_serviceV3(
        at_verification_key_provider, backend, sign_header_policy);
    security::SignConfirm sign_confirm = sign_service(std::move(sign_request));
    asn1::EtsiTs103097Data signed_inner_at_request_wrapped;
    signed_inner_at_request_wrapped.decode(
        boost::get<security::SecuredMessageV3>(sign_confirm.secured_message).serialize());

    // Encrypt the signed inner_at_request_wrapped for the AA
    DownPacket packet_signed_inner_at_request_wrapped;
    packet_signed_inner_at_request_wrapped.layer(OsiLayer::Application) =
        std::move(signed_inner_at_request_wrapped);

    security::EncryptRequest encrypt_request{
        std::move(packet_signed_inner_at_request_wrapped), aa_certificate};
    security::EncryptService encrypt_service = security::straight_encrypt_serviceV3(backend);
    security::EncryptConfirm encrypt_confirm = encrypt_service(encrypt_request);

    return encrypt_confirm;
}

asn1::EtsiTs103097Certificate
decode_at_response(const security::SecuredMessageV3 &at_response,
                   const std::array<uint8_t, 16> &session_key,
                   security::SecurityEntity &security_entity)
{
    // Decrypt the response
    assert(at_response.is_encrypted_message());
    security::BackendOpenSsl backend;
    security::DecryptService decrypt_service = security::straight_decrypt_serviceV3(backend);
    security::DecryptRequest decrypt_request { at_response, session_key };
    security::DecryptConfirm decrypt_response = decrypt_service(decrypt_request);

    // Check signature
    vanetza::security::SecuredMessageVariant sec_packet = decrypt_response.decrypted_message;
    vanetza::security::DecapRequest decap_request(sec_packet);
    auto decap_res = security_entity.decapsulate_packet(std::move(decap_request));
    assert(decap_res.report == vanetza::security::DecapReport::Success);

    // Decode the EtsiTs102941Data structure
    const vanetza::ByteBuffer etsi_ts_102_941_data_bb = decrypt_response.decrypted_message.get_payload();
    vanetza::asn1::EtsiTs102941Data etsi_ts_102_941_data;
    etsi_ts_102_941_data.decode(etsi_ts_102_941_data_bb);
    // Check for correct reponse type
    assert(etsi_ts_102_941_data->content.present == EtsiTs102941DataContent_PR_authorizationResponse);

    const InnerAtResponse_t &inner_at_response = etsi_ts_102_941_data->content.choice.authorizationResponse;
    // Check for successful response
    assert(inner_at_response.responseCode == EnrolmentResponseCode_ok);

    // Copy the certificate into the return value
    const vanetza::ByteBuffer ec_bb = vanetza::asn1::encode_oer(
        asn_DEF_EtsiTs103097Certificate, inner_at_response.certificate);
    vanetza::asn1::EtsiTs103097Certificate ec;
    ec.decode(ec_bb);

    return ec;
}

} // namespace pki

} // namespace vanetza
