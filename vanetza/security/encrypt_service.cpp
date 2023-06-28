#include <vanetza/security/encrypt_service.hpp>
#include <vanetza/security/sha.hpp>

namespace vanetza
{
namespace security
{

EncryptService straight_encrypt_serviceV3(BackendOpenSsl& backend)
{
    return [&backend](const EncryptRequest& request) {
        const CertificateV3 &target_certificate = request.target_certificate;

        auto public_key = target_certificate.get_encryption_public_key(backend);
        auto curve_name = target_certificate.get_encryption_public_key_curve_name();
        if (!public_key || !curve_name) {
            throw std::runtime_error("Target certificate has no valid public key");
        }

        // Get shared info for KDF input
        ByteBuffer target_certificate_oer = target_certificate.serialize();
        Sha256Digest shared_info = calculate_sha256_digest(target_certificate_oer.data(), target_certificate_oer.size());
        ByteBuffer shared_info_bb(shared_info.begin(), shared_info.end());

        ByteBuffer data = convert_to_payload(request.plain_message);

        // Encrypt data with ECIES and AES-CCM
        EciesEncryptionResult encryption_res = backend.encrypt_data(*public_key, *curve_name, data, shared_info_bb);

        // Append AES tag to ciphertext
        const std::array<uint8_t, 16> &aes_tag = encryption_res.aes_tag;
        ByteBuffer merged_aes_data = encryption_res.aes_ciphertext;
        merged_aes_data.insert(merged_aes_data.end(), aes_tag.begin(), aes_tag.end());

        // Wrap everything in EncryptConfirm
        EncryptConfirm confirm { SecuredMessageV3(true), encryption_res.aes_key };
        SecuredMessageV3 &secured_message = confirm.secured_message;
        secured_message.set_aes_ccm_ciphertext(merged_aes_data, encryption_res.aes_nonce);

        HashedId8 signer_info = target_certificate.calculate_hash();
        secured_message.add_cert_recip_info(
            signer_info, *curve_name, encryption_res.ecies_ciphertext,
            encryption_res.ecies_tag, encryption_res.ecies_pub_key);

        return confirm;
    };
}

} // namespace security
} // namespace vanetza
