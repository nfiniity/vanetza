#include <vanetza/security/sign_header_policy.hpp>
#include <vanetza/security/encrypt_service.hpp>

namespace vanetza
{
namespace security
{

EncryptService straight_encrypt_serviceV3(BackendOpenSsl& backend)
{
    return [&backend](EncryptRequest&& request) {
        const CertificateV3 &target_certificate = request.target_certificate;

        auto public_key = target_certificate.get_public_key(backend);
        auto curve_name = target_certificate.get_public_key_curve_name();
        if (!public_key || !curve_name) {
            throw std::runtime_error("Target certificate has no valid public key");
        }

        HashedId8 signer_info = target_certificate.calculate_hash();
        ByteBuffer shared_info(signer_info.begin(), signer_info.end());

        ByteBuffer data = convert_to_payload(request.plain_message);

        EciesEncryptionResult encryption_res = backend.encrypt_data(*public_key, *curve_name, data, shared_info);

        const std::array<uint8_t, 16> &aes_tag = encryption_res.aes_tag;
        ByteBuffer merged_aes_data = encryption_res.aes_ciphertext;
        merged_aes_data.insert(merged_aes_data.end(), aes_tag.begin(), aes_tag.end());

        EncryptConfirm confirm { SecuredMessageV3(true) };
        SecuredMessageV3 &secured_message = confirm.secured_message;
        secured_message.set_aes_ccm_ciphertext(merged_aes_data, encryption_res.aes_nonce);
        secured_message.add_cert_recip_info(
            signer_info, *curve_name, encryption_res.ecies_ciphertext,
            encryption_res.ecies_tag, encryption_res.ecies_pub_key);

        // TODO: save session key
        return confirm;
    };
}

} // namespace security
} // namespace vanetza
