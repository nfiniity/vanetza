#include <vanetza/security/decrypt_service.hpp>

namespace vanetza
{
namespace security
{

DecryptService straight_decrypt_serviceV3(BackendOpenSsl& backend)
{
    return [&backend](const DecryptRequest& request) {
        const SecuredMessageV3 &encrypted_message = request.encrypted_message;
        if (!encrypted_message.is_encrypted_message()) {
            throw std::runtime_error("SN-DECRYPT.request: message is not encrypted");
        }
        if (!encrypted_message.check_psk_match(request.session_key)) {
            throw std::runtime_error("SN-DECRYPT.request: Session key does not match");
        }

        // Split ciphertext and tag
        const AesCcmCiphertext msg_ciphertext = encrypted_message.get_aes_ccm_ciphertext();
        const auto &ciphertext_and_tag = msg_ciphertext.ciphertext_and_tag;
        if (ciphertext_and_tag.size() < 16) {
            throw std::runtime_error("SN-DECRYPT.request: ciphertext too short");
        }

        ByteBuffer ciphertext(ciphertext_and_tag.begin(), ciphertext_and_tag.end() - 16);
        std::array<uint8_t, 16> tag;
        std::copy(ciphertext_and_tag.end() - 16, ciphertext_and_tag.end(), tag.begin());

        // Decrypt data
        ByteBuffer decryption_res = backend.aes_ccm_decrypt(
            request.session_key, msg_ciphertext.nonce, ciphertext, tag);

        DecryptConfirm confirm { SecuredMessageV3(decryption_res) };

        return confirm;
    };
}

} // namespace security
} // namespace vanetza
