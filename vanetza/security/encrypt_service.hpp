#ifndef ENCRYPT_SERVICE_HPP_8CD77F6A
#define ENCRYPT_SERVICE_HPP_8CD77F6A

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/net/packet.hpp>
#include <vanetza/security/int_x.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signer_info.hpp>
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
    ItsAid its_aid;
    ByteBuffer permissions;
};

// mandatory SN-SIGN.confirm parameters
struct SignConfirm
{
    SecuredMessageVariant secured_message;
};


/**
 * Equivalant of SN-ENCRYPT service in TS 102 723-8 v1.1.1
 */
using EncryptService = std::function<SignConfirm(EncryptRequest&&)>;

EncryptService straight_encrypt_serviceV3(CertificateProvider& certificate_provider, Backend& backend, SignHeaderPolicy& sign_header_policy);

} // namespace security
} // namespace vanetza

#endif /* ENCRYPT_SERVICE_HPP_8CD77F6A */
