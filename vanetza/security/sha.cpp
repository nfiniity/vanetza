#include <vanetza/security/sha.hpp>
#ifdef VANETZA_WITH_CRYPTOPP
#include <cryptopp/sha.h>
#endif
#ifdef VANETZA_WITH_OPENSSL
#include <openssl/sha.h>
#endif

namespace vanetza
{
namespace security
{

Sha256Digest calculate_sha256_digest(const uint8_t* data, std::size_t len)
{
    Sha256Digest digest;
#if defined VANETZA_WITH_OPENSSL
    static_assert(SHA256_DIGEST_LENGTH == digest.size(), "size of OpenSSL SHA256_DIGEST_LENGTH does not match");
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(digest.data(), &ctx);
#elif defined VANETZA_WITH_CRYPTOPP
    static_assert(CryptoPP::SHA256::DIGESTSIZE == digest.size(), "size of CryptoPP::SHA256 diges does not match");
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(digest.data(), data, len);
#else
#   error "no SHA256 implementation available"
#endif
    return digest;
}

Sha384Digest calculate_sha384_digest(const uint8_t* data, std::size_t len)
{
    Sha384Digest digest;
#if defined VANETZA_WITH_OPENSSL
    static_assert(SHA384_DIGEST_LENGTH == digest.size(), "size of OpenSSL SHA384_DIGEST_LENGTH does not match");
    SHA512_CTX ctx;
    SHA384_Init(&ctx);
    SHA384_Update(&ctx, data, len);
    SHA384_Final(digest.data(), &ctx);
#elif defined VANETZA_WITH_CRYPTOPP
    static_assert(CryptoPP::SHA384::DIGESTSIZE == digest.size(), "size of CryptoPP::SHA384 diges does not match");
    CryptoPP::SHA384 hash;
    hash.CalculateDigest(digest.data(), data, len);
#else
#   error "no SHA384 implementation available"
#endif
    return digest;
}

ByteBuffer calculate_sha_signature_inputV3(const ByteBuffer &tbs_data,
                                           const CertificateV3 &certificate,
                                           const std::string &curve_name)
{
    // Check is the certificate is self-signed
    bool self_signed = certificate.get_issuer_identifier() == HashedId8{{0, 0, 0, 0, 0, 0, 0, 0}};
    ByteBuffer signer_data {};
    if (!self_signed) {
        signer_data = certificate.serialize();
    }

    // Calculate tbs_data and signer digests
    ByteBuffer signer_digest;
    ByteBuffer tbs_data_digest;
    if (curve_name == "prime256v1" || curve_name == "brainpoolP256r1") {
        auto signer_digest_array = calculate_sha256_digest(signer_data.data(), signer_data.size());
        signer_digest = ByteBuffer(signer_digest_array.begin(), signer_digest_array.end());

        auto tbs_data_digest_array = calculate_sha256_digest(tbs_data.data(), tbs_data.size());
        tbs_data_digest = ByteBuffer(tbs_data_digest_array.begin(), tbs_data_digest_array.end());
    } else if (curve_name == "brainpoolP384r1") {
        auto signer_digest_array = calculate_sha384_digest(signer_data.data(), signer_data.size());
        signer_digest = ByteBuffer(signer_digest_array.begin(), signer_digest_array.end());

        auto tbs_data_digest_array = calculate_sha384_digest(tbs_data.data(), tbs_data.size());
        tbs_data_digest = ByteBuffer(tbs_data_digest_array.begin(), tbs_data_digest_array.end());
    } else {
        throw std::runtime_error("Unsupported curve name");
    }

    // Concatenate the two digests
    ByteBuffer result(tbs_data_digest.size() + signer_digest.size());
    std::copy(tbs_data_digest.begin(), tbs_data_digest.end(), result.begin());
    std::copy(signer_digest.begin(), signer_digest.end(), result.begin() + tbs_data_digest.size());

    return result;
}

} // namespace security
} // namespace vanetza
