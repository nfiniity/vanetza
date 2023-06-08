#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <cassert>

namespace vanetza
{
namespace security
{

BackendOpenSsl::BackendOpenSsl()
{
#if OPENSSL_API_COMPAT < 0x10100000L
    ERR_load_crypto_strings();
#else
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#endif
}

EcdsaSignature BackendOpenSsl::sign_data(const ecdsa256::PrivateKey& key, const ByteBuffer& data)
{
    auto priv_key = internal_private_key(key);
    auto digest = calculate_digest(data);

    // sign message data represented by the digest
    openssl::Signature signature { ECDSA_do_sign(digest.data(), digest.size(), priv_key) };
#if OPENSSL_API_COMPAT < 0x10100000L
    const BIGNUM* sig_r = signature->r;
    const BIGNUM* sig_s = signature->s;
#else
    const BIGNUM* sig_r = nullptr;
    const BIGNUM* sig_s = nullptr;
    ECDSA_SIG_get0(signature, &sig_r, &sig_s);
#endif

    EcdsaSignature ecdsa_signature;
    X_Coordinate_Only coordinate;

    if (sig_r && sig_s) {
        const size_t len = field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);

        const auto num_bytes_s = BN_num_bytes(sig_s);
        assert(len >= static_cast<size_t>(num_bytes_s));
        ecdsa_signature.s.resize(len, 0x00);
        BN_bn2bin(sig_s, ecdsa_signature.s.data() + len - num_bytes_s);

        const auto num_bytes_r = BN_num_bytes(sig_r);
        assert(len >= static_cast<size_t>(num_bytes_r));
        coordinate.x.resize(len, 0x00);
        BN_bn2bin(sig_r, coordinate.x.data() + len - num_bytes_r);
    } else {
        throw openssl::Exception();
    }

    ecdsa_signature.R = std::move(coordinate);
    return ecdsa_signature;
}

ByteBuffer BackendOpenSsl::encrypt_data(const ecdsa256::PublicKey& key, const std::string& curve_name, const ByteBuffer& data) const
{
    /*
        NOTE: It is important that the nonce of CCM should be carefully chosen to never be used more than once for a given key.
              To avoid timing attacks, the output of decryption should be given after performing all the computations
              even if it outputs failed.
    */

    // Generate random symmetric key for AES-CCM
    std::array<uint8_t, 16> aes_key;

    openssl::check(1 == RAND_bytes(aes_key.data(), aes_key.size()));

    // Generate random nonce for AES-CCM
    std::array<uint8_t, 12> aes_nonce;

    openssl::check(1 == RAND_bytes(aes_nonce.data(), aes_nonce.size()));

    // Encrypt data with AES-CCM
    ByteBuffer encrypted_data;
    std::array<uint8_t, 16> encrypted_data_tag;

    ccm_encrypt(data, aes_key, aes_nonce, encrypted_data, encrypted_data_tag);

    // Convert recipient public key to OpenSSL EVP_PKEY
    openssl::EvpKey recipient_key(key, curve_name);

    // Generate ephemeral key pair for ECIES
    openssl::EvpKey ephemeral_key(curve_name);

    // Derive shared secret from ephemeral private key and public key
    std::array<uint8_t, 32> shared_secret(ecdh_secret(ephemeral_key, recipient_key));

    // Derive encryption and signing keys for AES key encryption from shared secret with SHA-256 (concatenate counter 4 octets)
    std::array<uint8_t, 16> ecies_encryption_key;
    std::array<uint8_t, 32> ecies_mac_key;
    ecies_keys(shared_secret, ecies_encryption_key, ecies_mac_key);

    // Encrypt AES key with XOR using ECIES encryption key
    std::array<uint8_t, 16> encrypted_aes_key(xor_encrypt_decrypt(ecies_encryption_key, aes_key));

    // Calculate HMAC on encrypted AES key using ECIES signing key
    ByteBuffer ecies_mac_key_bb(ecies_mac_key.begin(), ecies_mac_key.end());
    ByteBuffer encrypted_aes_key_bb(encrypted_aes_key.begin(), encrypted_aes_key.end());
    std::array<uint8_t, 32> encrypted_aes_key_hmac(hmac_sha256(ecies_mac_key_bb, encrypted_aes_key_bb));

    // Store AES key (and nonce?) for response decryption

    // Cleanup

    return data; // TODO
}

bool BackendOpenSsl::verify_data(const ecdsa256::PublicKey& key, const ByteBuffer& data, const EcdsaSignature& sig)
{
    auto digest = calculate_digest(data);
    auto pub = internal_public_key(key);
    openssl::Signature signature(sig);

    return (ECDSA_do_verify(digest.data(), digest.size(), signature, pub) == 1);
}

boost::optional<Uncompressed> BackendOpenSsl::decompress_point(const EccPoint& ecc_point)
{
    struct DecompressionVisitor : public boost::static_visitor<bool>
    {
        bool operator()(const X_Coordinate_Only&)
        {
            return false;
        }

        bool operator()(const Compressed_Lsb_Y_0& p)
        {
            return decompress(p.x, 0);
        }

        bool operator()(const Compressed_Lsb_Y_1& p)
        {
            return decompress(p.x, 1);
        }

        bool operator()(const Uncompressed& p)
        {
            result = p;
            return true;
        }

        bool decompress(const ByteBuffer& x, int y_bit)
        {
            openssl::BigNumberContext ctx;
            openssl::BigNumber x_coordinate(x);
            openssl::Group group(NID_X9_62_prime256v1);
            openssl::Point point(group);
            openssl::BigNumber y_coordinate;

            result.x = x;
            result.y.resize(result.x.size());

#if OPENSSL_API_COMPAT < 0x10101000L
            EC_POINT_set_compressed_coordinates_GFp(group, point, x_coordinate, y_bit, ctx);
            EC_POINT_get_affine_coordinates_GFp(group, point, nullptr, y_coordinate, ctx);
            std::size_t y_coordinate_bytes = BN_num_bytes(y_coordinate);
            if (y_coordinate_bytes <= result.y.size()) {
                BN_bn2bin(y_coordinate, result.y.data() + (result.y.size() - y_coordinate_bytes));
                return true;
            } else {
                return false;
            }
#else
            EC_POINT_set_compressed_coordinates(group, point, x_coordinate, y_bit, ctx);
            EC_POINT_get_affine_coordinates(group, point, nullptr, y_coordinate, ctx);
            return (BN_bn2binpad(y_coordinate, result.y.data(), result.y.size()) != -1);
#endif
        }

        Uncompressed result;
    };

    DecompressionVisitor visitor;
    if (boost::apply_visitor(visitor, ecc_point)) {
        return visitor.result;
    } else {
        return boost::none;
    }
}

std::array<uint8_t, 32> BackendOpenSsl::calculate_digest(const ByteBuffer& data) const
{
    static_assert(SHA256_DIGEST_LENGTH == 32, "Unexpected length of SHA256 digest");

    std::array<uint8_t, 32> digest;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(digest.data(), &ctx);
    return digest;
}

openssl::Key BackendOpenSsl::internal_private_key(const ecdsa256::PrivateKey& generic) const
{
    openssl::Key key(NID_X9_62_prime256v1);
    openssl::BigNumber prv(generic.key);
    EC_KEY_set_private_key(key, prv);

    // OpenSSL requires public key, so we recreate it from private key
    openssl::BigNumberContext ctx;
    const EC_GROUP* group = EC_KEY_get0_group(key);
    openssl::Point pub(group);
    openssl::check(EC_POINT_mul(group, pub, prv, nullptr, nullptr, ctx));
    EC_KEY_set_public_key(key, pub);

    openssl::check(EC_KEY_check_key(key));
    return key;
}

openssl::Key BackendOpenSsl::internal_public_key(const ecdsa256::PublicKey& generic) const
{
    openssl::Key key(NID_X9_62_prime256v1);
    openssl::BigNumber x(generic.x);
    openssl::BigNumber y(generic.y);
    EC_KEY_set_public_key_affine_coordinates(key, x, y);

    openssl::check(EC_KEY_check_key(key));
    return key;
}

int BackendOpenSsl::ccm_encrypt(const ByteBuffer &plaintext, const std::array<uint8_t, 16> &key,
                                const std::array<uint8_t, 12> &iv, ByteBuffer &ciphertext, std::array<uint8_t, 16> &tag) const
{
    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    openssl::check(ctx != nullptr);

    // Set IV length to 12 bytes and tag length to 16 bytes
    std::array<OSSL_PARAM, 3> cipher_params;
    size_t iv_len = iv.size();
    cipher_params[0] = OSSL_PARAM_construct_size_t("ivlen", &iv_len);
    cipher_params[1] = OSSL_PARAM_construct_octet_string("tag", nullptr, tag.size());
    cipher_params[2] = OSSL_PARAM_construct_end();

    /* Initialise the encryption operation. */
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(nullptr, "AES-128-CCM", nullptr);
    openssl::check(cipher != nullptr &&
                   1 == EVP_EncryptInit_ex2(ctx, cipher, nullptr, nullptr, cipher_params.data()) &&
                   1 == EVP_EncryptInit_ex2(ctx, nullptr, key.data(), iv.data(), nullptr));

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can only be called once for this.
     */
    ciphertext.resize(plaintext.size());

    openssl::check(1 == EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())));
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in CCM mode.
     */
    openssl::check(1 == EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len));
    ciphertext_len += len;
    assert(len == 0);

    /* Get the tag */
    std::array<OSSL_PARAM, 2> tag_params;
    tag_params[0] = OSSL_PARAM_construct_octet_string("tag", tag.data(), tag.size());
    tag_params[1] = OSSL_PARAM_construct_end();
    openssl::check(1 == EVP_CIPHER_CTX_get_params(ctx, tag_params.data()));

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);

    return ciphertext_len;
}

std::array<uint8_t, 32> BackendOpenSsl::ecdh_secret(openssl::EvpKey &private_key, openssl::EvpKey &public_key) const
{
    std::array<uint8_t, 32> result;
    size_t len;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, private_key, nullptr);
    openssl::check(ctx != nullptr &&
                   1 == EVP_PKEY_derive_init(ctx) &&
                   1 == EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, 1) && // Enable cofactor mode
                   1 == EVP_PKEY_derive_set_peer(ctx, public_key) &&
                   1 == EVP_PKEY_derive(ctx, result.data(), &len));

    assert(len == result.size());
    EVP_PKEY_CTX_free(ctx);

    return result;
}

void BackendOpenSsl::ecies_keys(const std::array<uint8_t, 32> &shared_secret,
                   std::array<uint8_t, 16> &encryption_key,
                   std::array<uint8_t, 32> &mac_key) const
{
    // Input for encryption_key is shared secret and 0x000001
    std::array<uint8_t, 36> input;
    std::copy(shared_secret.begin(), shared_secret.end(), input.begin());
    input[32] = 0x00;
    input[33] = 0x00;
    input[34] = 0x00;
    input[35] = 0x01;

    std::array<uint8_t, 32> encryption_digest;
    openssl::check(SHA256(input.data(), input.size(), encryption_digest.data()) != nullptr);
    std::copy(encryption_digest.begin(), encryption_digest.begin() + encryption_key.size(), encryption_key.begin());

    // Input for mac_key is shared secret and 0x000002
    input[35] = 0x02;
    openssl::check(SHA256(input.data(), input.size(), mac_key.data()) != nullptr);
}

template <std::size_t N>
std::array<uint8_t, N> BackendOpenSsl::xor_encrypt_decrypt(const std::array<uint8_t, N> &key,
                                                           const std::array<uint8_t, N> &data) const
{
    std::array<uint8_t, N> output;
    for (std::size_t i = 0; i < N; ++i) {
        output[i] = key[i] ^ data[i];
    }
    return output;
}

std::array<uint8_t, 32> BackendOpenSsl::hmac_sha256(const ByteBuffer &key,
                                                    const ByteBuffer &data) const
{
    EVP_MD *digest = EVP_MD_fetch(nullptr, "SHA256", nullptr);

    std::array<uint8_t, 32> result;
    unsigned int hmac_len;
    openssl::check(HMAC(digest, key.data(), key.size(), data.data(), data.size(),
                        result.data(), &hmac_len) != nullptr);
    assert(hmac_len == result.size());

    EVP_MD_free(digest);
    return result;
}

} // namespace security
} // namespace vanetza
