#ifndef SHA_HPP_ENSVKDXU
#define SHA_HPP_ENSVKDXU

#include <array>
#include <cstdint>

#include <vanetza/security/certificate.hpp>
#include <vanetza/common/byte_buffer.hpp>

namespace vanetza
{
namespace security
{

using Sha256Digest = std::array<uint8_t, 32>;

Sha256Digest calculate_sha256_digest(const uint8_t* data, std::size_t len);

/*
 *  Concatenate the hash of tbs_data with the whole certificate hash of the
 *  signer or an empty buffer hash if the signing key is embedded in the tbs_data.
 *  This is used as the data for sign_data in the backend.
 *  Defined in IEEE 1609.2 2022, Section 5.3.1.2.2
 */
ByteBuffer calculate_sha256_signature_inputV3(const ByteBuffer& tbs_data, const CertificateV3& certificate);

} // namespace security
} // namespace vanetza

#endif /* SHA_HPP_ENSVKDXU */

