#ifndef BACKEND_OPENSSL_HPP_CRRV8DCH
#define BACKEND_OPENSSL_HPP_CRRV8DCH

#include <boost/optional.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{

struct EciesEncryptionResult
{
    // AES-128-CCM on the message
    ByteBuffer aes_ciphertext;
    std::array<uint8_t, 16> aes_tag;
    std::array<uint8_t, 12> aes_nonce;
    std::array<uint8_t, 16> aes_key;

    // ECIES on the AES key
    std::array<uint8_t, 16> ecies_ciphertext;
    std::array<uint8_t, 16> ecies_tag;
    ecdsa256::PublicKey ecies_pub_key;

};

struct EciesKeys
{
    std::array<uint8_t, 16> encryption_key;
    std::array<uint8_t, 32> mac_key;
};

/**
 * \brief Backend implementation based on OpenSSL
 */
class BackendOpenSsl : public Backend
{
public:
    static constexpr auto backend_name = "OpenSSL";

    BackendOpenSsl();

    /// \see Backend::sign_data
    EcdsaSignature sign_data(const ecdsa256::PrivateKey& private_key, const ByteBuffer& data_buffer) override;

    /*
     * Encrypt data using ECIES with AES-128-CCM and SHA256-HMAC
     * as described in IEEE 1363a 2004 Section 11.3, IEEE 1609.2 Section 5.3.5 and ETSI TS 102 941 V1.4.1 Annex F
     * \param public_key public key of recipient
     * \param curve_name name of curve of public key
     * \param data data to encrypt
     * \param shared_info additional data to be included in the ECIES encryption key derivation
     * \return encryption result
    */
    EciesEncryptionResult encrypt_data(const ecdsa256::PublicKey &public_key, const std::string &curve_name,
                                       const ByteBuffer &data, const ByteBuffer &shared_info) const;

    // Only use this directly for testing, otherwise use the overload without ephemeral and aes keys
    EciesEncryptionResult encrypt_data(const ecdsa256::PublicKey &public_key, const std::string &curve_name,
                                       const ByteBuffer &data, const ByteBuffer &shared_info,
                                       const std::array<uint8_t, 16> &aes_key, openssl::EvpKey &ephemeral_key) const;

    /// \see Backend::verify_data
    bool verify_data(const ecdsa256::PublicKey& public_key, const ByteBuffer& data, const EcdsaSignature& sig) override;

    /// \see Backend::decompress_point
    boost::optional<Uncompressed> decompress_point(const EccPoint& ecc_point, const std::string& curve_name = "prime256v1") override;

    int aes_ccm_encrypt(const ByteBuffer &plaintext,
                        const std::array<uint8_t, 16> &key,
                        const std::array<uint8_t, 12> &iv,
                        ByteBuffer &ciphertext,
                        std::array<uint8_t, 16> &tag) const;

    // key derivation function
    ByteBuffer kdf2_sha256(ByteBuffer &shared_secret, ByteBuffer &shared_info, size_t output_len) const;

    // HMAC with SHA256
    std::array<uint8_t, 16> hmac_sha256(const ByteBuffer &key, const ByteBuffer &data) const;

private:
    /// Calculate SHA256 digest of data buffer
    std::array<uint8_t, 32> calculate_digest(const ByteBuffer& data) const;

    /// Convert to internal format of private key
    openssl::Key internal_private_key(const ecdsa256::PrivateKey&) const;

    /// Convert to internal format of public key
    openssl::Key internal_public_key(const ecdsa256::PublicKey&) const;

    // Derive encryption and signing keys for AES key encryption using ECIES
    EciesKeys get_ecies_keys(openssl::EvpKey &private_key, openssl::EvpKey &public_key, ByteBuffer shared_info) const;

    // XOR cipher
    template <std::size_t N>
    std::array<uint8_t, N> xor_encrypt_decrypt(const std::array<uint8_t, N> &key,
                                               const std::array<uint8_t, N> &input) const;
};

} // namespace security
} // namespace vanetza

#endif /* BACKEND_OPENSSL_HPP_CRRV8DCH */
