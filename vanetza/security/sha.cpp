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

ByteBuffer calculate_sha256_signature_inputV3(const ByteBuffer& tbs_data, const CertificateV3& certificate)
{
    // Calculate tbs_data digest
    Sha256Digest tbs_data_digest = calculate_sha256_digest(tbs_data.data(), tbs_data.size());

    // Check is the certificate is self-signed
    bool self_signed = certificate.get_issuer_identifier() == HashedId8{{0, 0, 0, 0, 0, 0, 0, 0}};

    // Calculate the digest of the signer
    Sha256Digest signer_digest;
    if (self_signed) {
        ByteBuffer empty_buffer{};
        signer_digest = calculate_sha256_digest(empty_buffer.data(), empty_buffer.size());
    } else {
        signer_digest = calculate_sha256_digest(certificate.get_issuer_identifier().data(),
                                                certificate.get_issuer_identifier().size());
    }

    // Concatenate the two digests
    ByteBuffer result(tbs_data_digest.size() + signer_digest.size());
    std::copy(tbs_data_digest.begin(), tbs_data_digest.end(), result.begin());
    std::copy(signer_digest.begin(), signer_digest.end(), result.begin() + tbs_data_digest.size());

    return result;
}

} // namespace security
} // namespace vanetza
