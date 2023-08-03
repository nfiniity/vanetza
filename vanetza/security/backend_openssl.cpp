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
#include <openssl/kdf.h>
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

EcdsaSignature BackendOpenSsl::sign_data(const ecdsa256::PrivateKey &key,
                                         const ByteBuffer &data,
                                         const std::string &curve_name)
{
    openssl::EvpKey priv_key(curve_name, key);

    // Set up signing context
    std::string digest_name;
    if (curve_name == "prime256v1" || curve_name == "brainpoolP256r1") {
        digest_name = "SHA256";
    } else if (curve_name == "brainpoolP384r1") {
        digest_name = "SHA384";
    } else {
        throw std::runtime_error("Unsupported curve name");
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    openssl::check(nullptr != ctx &&
                   1 == EVP_DigestSignInit_ex(ctx, nullptr, digest_name.data(), nullptr, nullptr, priv_key, nullptr));

    // Get required buffer size
    size_t sig_len;
    openssl::check(1 == EVP_DigestSign(ctx, nullptr, &sig_len, data.data(), data.size()));
    // Sign data
    ByteBuffer sig_buf(sig_len);
    openssl::check(1 == EVP_DigestSign(ctx, sig_buf.data(), &sig_len, data.data(), data.size()));

    EVP_MD_CTX_free(ctx);

    // Convert OpenSSL signature to EcdsaSignature
    const unsigned char *sig_ptr = sig_buf.data();
    ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(nullptr, &sig_ptr, sig_len);
    openssl::check(ecdsa_sig != nullptr);
    return openssl::Signature(ecdsa_sig, digest_name).ecdsa_signature();
}

EciesEncryptionResult BackendOpenSsl::encrypt_data(
    const ecdsa256::PublicKey &public_key, const std::string &curve_name,
    const ByteBuffer &data, const ByteBuffer &shared_info) const
{
    // Generate random symmetric key for AES-CCM
    std::array<uint8_t, 16> aes_key;
    openssl::check(1 == RAND_bytes(aes_key.data(), aes_key.size()));

    // Generate ephemeral key pair for ECIES
    openssl::EvpKey ephemeral_key(curve_name);

    return encrypt_data(public_key, curve_name, data, shared_info, aes_key, ephemeral_key);
}

EciesEncryptionResult BackendOpenSsl::encrypt_data(
    const ecdsa256::PublicKey &public_key, const std::string &curve_name,
    const ByteBuffer &data, const ByteBuffer &shared_info,
    const std::array<uint8_t, 16> &aes_key, openssl::EvpKey &ephemeral_key) const
{
    EciesEncryptionResult result;
    result.aes_key = aes_key;

    // Generate random nonce for AES-CCM
    auto &aes_nonce = result.aes_nonce;
    openssl::check(1 == RAND_bytes(aes_nonce.data(), aes_nonce.size()));

    // Encrypt data with AES-CCM
    aes_ccm_encrypt(data, aes_key, aes_nonce, result.aes_ciphertext, result.aes_tag);

    // Convert recipient public key to OpenSSL EVP_PKEY
    openssl::EvpKey recipient_key(curve_name, boost::none, public_key);

    // Get public ephemeral key for ECIES
    result.ecies_pub_key = boost::get<asn1::EccP256CurvePoint>(ephemeral_key.ecc_curve_point());

    // Derive encryption and signing keys for AES key encryption using ECIES
    EciesKeys ecies_keys = get_ecies_keys(ephemeral_key, recipient_key, shared_info);

    // Encrypt AES key with XOR using ECIES encryption key
    auto &ecies_ciphertext = result.ecies_ciphertext;
    ecies_ciphertext = xor_encrypt_decrypt(ecies_keys.encryption_key, aes_key);

    // Calculate HMAC on encrypted AES key using ECIES signing key
    ByteBuffer ecies_mac_key_bb(ecies_keys.mac_key.begin(), ecies_keys.mac_key.end());
    ByteBuffer encrypted_aes_key_bb(ecies_ciphertext.begin(), ecies_ciphertext.end());
    result.ecies_tag = hmac_sha256(ecies_mac_key_bb, encrypted_aes_key_bb);

    return result;
}

bool BackendOpenSsl::verify_data(const ecdsa256::PublicKey &key,
                                 const ByteBuffer &data,
                                 const EcdsaSignature &sig,
                                 const std::string &curve_name) {
    // Prepare public key
    openssl::EvpKey pub_key(curve_name, boost::none, key);

    // Configure verification parameters
    std::string digest_name;
    if (curve_name == "prime256v1" || curve_name == "brainpoolP256r1") {
        digest_name = "SHA256";
    } else if (curve_name == "brainpoolP384r1") {
        digest_name = "SHA384";
    } else {
        throw std::runtime_error("Unsupported curve name");
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    openssl::check(nullptr != ctx &&
                   1 == EVP_DigestVerifyInit_ex(ctx, nullptr, digest_name.data(), nullptr, nullptr, pub_key, nullptr));

    // Convert signature to ASN.1 format
    openssl::Signature asn1_sig(sig, digest_name);
    unsigned char *asn1_sig_encoded = nullptr;
    int asn1_sig_encoded_len = i2d_ECDSA_SIG(asn1_sig, &asn1_sig_encoded);
    openssl::check(asn1_sig_encoded_len > 0);

    // Verify signature
    int res = EVP_DigestVerify(ctx, asn1_sig_encoded, asn1_sig_encoded_len, data.data(), data.size());
    // Values smaller than 0 indicate an error
    openssl::check(res >= 0);

    EVP_MD_CTX_free(ctx);

    return res == 1;
}

boost::optional<Uncompressed> BackendOpenSsl::decompress_point(const EccPoint& ecc_point, const std::string& curve_name)
{
    struct DecompressionVisitor : public boost::static_visitor<bool>
    {
        explicit DecompressionVisitor(const std::string &curve_name)
        {
            if (curve_name == "prime256v1") {
                curve = NID_X9_62_prime256v1;
            } else if (curve_name == "brainpoolP256r1") {
                curve = NID_brainpoolP256r1;
            } else if (curve_name == "brainpoolP384r1") {
                curve = NID_brainpoolP384r1;
            } else {
                throw std::invalid_argument("Unsupported curve name");
            }
        }

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
            openssl::Group group(curve);
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
        int curve;
    };

    DecompressionVisitor visitor(curve_name);
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

int BackendOpenSsl::aes_ccm_encrypt(const ByteBuffer &plaintext, const std::array<uint8_t, 16> &key,
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

ByteBuffer BackendOpenSsl::aes_ccm_decrypt(const std::array<uint8_t, 16> &key,
                                           const std::array<uint8_t, 12> &iv,
                                           const ByteBuffer &ciphertext,
                                           std::array<uint8_t, 16> &tag) const
{
    int len;

    int plaintext_len;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    openssl::check(ctx != nullptr);

    // Set IV length to 12 bytes and tag length to 16 bytes
    std::array<OSSL_PARAM, 3> cipher_params;
    size_t iv_len = iv.size();
    cipher_params[0] = OSSL_PARAM_construct_size_t("ivlen", &iv_len);
    cipher_params[1] = OSSL_PARAM_construct_octet_string("tag", tag.data(), tag.size());
    cipher_params[2] = OSSL_PARAM_construct_end();

    /* Initialise the decryption operation. */
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(nullptr, "AES-128-CCM", nullptr);
    openssl::check(cipher != nullptr &&
                   1 == EVP_DecryptInit_ex2(ctx, cipher, nullptr, nullptr, cipher_params.data()) &&
                   1 == EVP_DecryptInit_ex2(ctx, nullptr, key.data(), iv.data(), nullptr));

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can only be called once for this.
     */
    ByteBuffer plaintext(ciphertext.size());

    openssl::check(1 == EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())));
    plaintext_len = len;

    /*
     * Finalise the decryption. Normally plaintext bytes may be written at
     * this stage, but this does not occur in CCM mode.
     */
    openssl::check(1 == EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len));
    plaintext_len += len;
    assert(len == 0);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);

    plaintext.resize(plaintext_len);
    return plaintext;
}

EciesKeys BackendOpenSsl::get_ecies_keys(openssl::EvpKey &private_key, openssl::EvpKey &public_key, ByteBuffer shared_info) const
{
    // Copy or create the P1 parameter used in the KDF, set0 takes ownership of the pointer.
    // If no shared_info is provided, use the hash of an empty string.
    // IEEE 1609.2 Section 5.3.5.1 Parameter P1
    unsigned char *kdf_ukm = nullptr;
    size_t kdf_ukm_len = 0;
    if (shared_info.size() > 0) {
        kdf_ukm = new unsigned char[shared_info.size()];
        std::copy(shared_info.begin(), shared_info.end(), kdf_ukm);
        kdf_ukm_len = shared_info.size();
    } else {
        const std::array<uint8_t, 32> empty_string_hash = calculate_digest(ByteBuffer {});
        kdf_ukm = new unsigned char[empty_string_hash.size()];
        std::copy(empty_string_hash.begin(), empty_string_hash.end(), kdf_ukm);
        kdf_ukm_len = empty_string_hash.size();
    }

    // Fetch the SHA256 digest for the KDF
    EVP_MD *digest = EVP_MD_fetch(nullptr, "SHA256", nullptr);
    std::array<uint8_t, 48> ecdh_kdf_result;
    size_t len = ecdh_kdf_result.size();

    // Run the key agreement and KDF in one step
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, private_key, nullptr);
    openssl::check(ctx != nullptr &&
                   1 == EVP_PKEY_derive_init(ctx) &&
                   1 == EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, 1) && // Enable cofactor mode
                   1 == EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, EVP_PKEY_ECDH_KDF_X9_63) &&
                   1 == EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, digest) &&
                   1 == EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx, kdf_ukm, kdf_ukm_len) &&
                   1 == EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, len) &&
                   1 == EVP_PKEY_derive_set_peer(ctx, public_key) &&
                   1 == EVP_PKEY_derive(ctx, ecdh_kdf_result.data(), &len));

    assert(len == ecdh_kdf_result.size());

    EVP_PKEY_CTX_free(ctx);
    EVP_MD_free(digest);

    // Extract the keys from the result
    EciesKeys keys;
    std::copy_n(ecdh_kdf_result.begin(), 16, keys.encryption_key.begin());
    std::copy_n(ecdh_kdf_result.begin() + 16, 32, keys.mac_key.begin());
    return keys;
}

ByteBuffer BackendOpenSsl::kdf2_sha256(ByteBuffer &shared_secret, ByteBuffer &shared_info, size_t output_len) const
{
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "X963KDF", nullptr);
    openssl::check(kdf != nullptr);
    EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(kdf);
    openssl::check(kdf_ctx != nullptr);

    std::array<OSSL_PARAM, 4> kdf_params;
    std::string digest("SHA256");
    kdf_params[0] = OSSL_PARAM_construct_utf8_string("digest", &digest[0], digest.size());
    kdf_params[1] = OSSL_PARAM_construct_octet_string("secret", shared_secret.data(), shared_secret.size());
    kdf_params[2] = OSSL_PARAM_construct_octet_string("info", shared_info.data(), shared_info.size());
    kdf_params[3] = OSSL_PARAM_construct_end();

    ByteBuffer result(output_len);
    openssl::check (1 == EVP_KDF_derive(kdf_ctx, result.data(), result.size(), kdf_params.data()));

    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kdf_ctx);
    return result;
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

std::array<uint8_t, 16> BackendOpenSsl::hmac_sha256(const ByteBuffer &key,
                                                    const ByteBuffer &data) const
{
    EVP_MD *digest = EVP_MD_fetch(nullptr, "SHA256", nullptr);
    openssl::check(nullptr != digest);

    std::array<uint8_t, 32> tmp;
    unsigned int hmac_len;
    openssl::check(HMAC(digest, key.data(), key.size(), data.data(), data.size(),
                        tmp.data(), &hmac_len) != nullptr);
    assert(hmac_len == tmp.size());

    EVP_MD_free(digest);

    std::array<uint8_t, 16> result;
    std::copy_n(tmp.begin(), result.size(), result.begin());
    return result;
}

ByteBuffer BackendOpenSsl::random_bytes(size_t len) const
{
    ByteBuffer result(len);
    openssl::check(1 == RAND_bytes(result.data(), result.size()));
    return result;
}

} // namespace security
} // namespace vanetza
