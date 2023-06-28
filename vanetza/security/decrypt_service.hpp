#ifndef DECRYPT_SERVICE_HPP_IG8YY9PC
#define DECRYPT_SERVICE_HPP_IG8YY9PC

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/backend_openssl.hpp>
#include <functional>

namespace vanetza
{

// forward declaration
class Runtime;

namespace security
{

// forward declarations
class Backend;
class CertificateProvider;
class SignHeaderPolicy;
class CertificateProviderV3;
class DefaultSignHeaderPolicyV3;

// mandatory SN-DECRYPT.request parameters
struct DecryptRequest
{
    SecuredMessageV3 encrypted_message;
    std::array<uint8_t, 16> session_key;
};

// mandatory SN-DECRYPT.confirm parameters
struct DecryptConfirm
{
    SecuredMessageV3 decrypted_message;
};


/**
 * Equivalant of SN-DECRYPT service in TS 102 723-8 v1.1.1
 */
using DecryptService = std::function<DecryptConfirm(const DecryptRequest&)>;

DecryptService straight_decrypt_serviceV3(BackendOpenSsl& backend);

} // namespace security
} // namespace vanetza

#endif /* DECRYPT_SERVICE_HPP_IG8YY9PC */
