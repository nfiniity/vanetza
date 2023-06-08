#ifndef BACKEND_OPENSSL_HPP_CRRV8DCH
#define BACKEND_OPENSSL_HPP_CRRV8DCH

#include <vanetza/security/backend.hpp>
#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{

// forward declaration
namespace openssl
{
class Key;
class EvpKey;
} // namespace openssl


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
     * as described in IEEE 1609.2 Section 5.3.5 and ETSI TS 102 941 V1.4.1 Annex F
     * \param public_key public key of recipient
     * \param curve_name name of curve of public key
     * \param data data to encrypt
     * \return encrypted data
    */
    ByteBuffer encrypt_data(const ecdsa256::PublicKey& public_key, const std::string &curve_name, const ByteBuffer& data) const;

    /// \see Backend::verify_data
    bool verify_data(const ecdsa256::PublicKey& public_key, const ByteBuffer& data, const EcdsaSignature& sig) override;

    /// \see Backend::decompress_point
    boost::optional<Uncompressed> decompress_point(const EccPoint& ecc_point) override;

    int aes_ccm_encrypt(const ByteBuffer &plaintext,
                        const std::array<uint8_t, 16> &key,
                        const std::array<uint8_t, 12> &iv,
                        ByteBuffer &ciphertext,
                        std::array<uint8_t, 16> &tag) const;


    // HMAC with SHA256
    std::array<uint8_t, 16> hmac_sha256(const ByteBuffer &key, const ByteBuffer &data) const;

private:
    /// calculate SHA256 digest of data buffer
    std::array<uint8_t, 32> calculate_digest(const ByteBuffer& data) const;

    /// convert to internal format of private key
    openssl::Key internal_private_key(const ecdsa256::PrivateKey&) const;

    /// convert to internal format of public key
    openssl::Key internal_public_key(const ecdsa256::PublicKey&) const;

    // calculate shared secret from ECDH (cofactor mode) key exchange
    std::array<uint8_t, 32> ecdh_secret(openssl::EvpKey &private_key, openssl::EvpKey &public_key) const;

    // derive encryption and MAC key from shared secret
    void ecies_keys(const std::array<uint8_t, 32> &shared_secret,
                       std::array<uint8_t, 16> &encryption_key,
                       std::array<uint8_t, 32> &mac_key) const;

    // XOR cipher
    template <std::size_t N>
    std::array<uint8_t, N> xor_encrypt_decrypt(const std::array<uint8_t, N> &key,
                                               const std::array<uint8_t, N> &input) const;
};

} // namespace security
} // namespace vanetza

#endif /* BACKEND_OPENSSL_HPP_CRRV8DCH */
