#ifndef ENCRYPT_SERVICE_HPP_8CD77F6A
#define ENCRYPT_SERVICE_HPP_8CD77F6A

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

// mandatory SN-ENCRYPT.request parameters
struct EncryptRequest
{
    DownPacket plain_message;
    CertificateV3 target_certificate;
};

// mandatory SN-SIGN.confirm parameters
struct EncryptConfirm
{
    SecuredMessageV3 secured_message;
};


/**
 * Equivalant of SN-ENCRYPT service in TS 102 723-8 v1.1.1
 */
using EncryptService = std::function<EncryptConfirm(EncryptRequest&&)>;

EncryptService straight_encrypt_serviceV3(BackendOpenSsl& backend);

} // namespace security
} // namespace vanetza

#endif /* ENCRYPT_SERVICE_HPP_8CD77F6A */
