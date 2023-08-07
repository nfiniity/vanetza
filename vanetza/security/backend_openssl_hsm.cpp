#include <vanetza/security/backend_openssl_hsm.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <cassert>

namespace vanetza
{
namespace security
{

BackendOpenSslHsm::BackendOpenSslHsm()
{
    // TODO: Test this
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_LOAD_CONFIG, nullptr);
}

} // namespace security
} // namespace vanetza
