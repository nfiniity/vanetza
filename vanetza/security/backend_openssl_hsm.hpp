#ifndef BACKEND_OPENSSLHSM_HPP_CA8412D4
#define BACKEND_OPENSSLHSM_HPP_CA8412D4

#include <vanetza/security/backend_openssl.hpp>
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
} // namespace openssl


/**
 * \brief Backend implementation based on OpenSSL with HSM support
 */
class BackendOpenSslHsm : public BackendOpenSsl
{
public:
    static constexpr auto backend_name = "OpenSSLHSM";

    BackendOpenSslHsm();
};

} // namespace security
} // namespace vanetza

#endif /* BACKEND_OPENSSLHSM_HPP_CA8412D4 */
