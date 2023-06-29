#ifndef SIGN_SERVICE_HPP_4MDQBSEF
#define SIGN_SERVICE_HPP_4MDQBSEF

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

// mandatory SN-SIGN.request parameters
struct SignRequest
{
    DownPacket plain_message;
    ItsAid its_aid;
    ByteBuffer permissions;
    PayloadTypeV3 message_type = PayloadTypeV3::RawUnsecured;
    bool external_payload = false;
};

// mandatory SN-SIGN.confirm parameters
struct SignConfirm
{
    SecuredMessageVariant secured_message;
};


/**
 * Equivalant of SN-SIGN service in TS 102 723-8 v1.1.1
 */
using SignService = std::function<SignConfirm(SignRequest&&)>;

/*
 * SignService immediately signing the message using given
 * \param rt runtime
 * \param cert certificate provider
 * \param backend cryptographic backend
 * \param sign_header_policy sign header policy
 * \return callable sign service
 */
SignService straight_sign_service(CertificateProvider&, Backend&, SignHeaderPolicy&);

/**
 * SignService deferring actually signature calculation using EcdsaSignatureFuture
 * \param rt runtime
 * \param cert certificate provider
 * \param backend cryptographic backend
 * \param sign_header_policy sign header policy
 * \return callable sign service
 */
SignService deferred_sign_service(CertificateProvider&, Backend&, SignHeaderPolicy&);

/**
 * SignService without real cryptography but dummy signature
 * \param rt runtime for appropriate generation time
 * \param si signer info attached to header fields of secured message
 * \return callable sign service
 */
SignService dummy_sign_service(const Runtime& rt, const SignerInfo& si);

/*
 * SignService immediately signing the message using given
 * \param rt runtime
 * \param cert certificate provider
 * \param backend cryptographic backend
 * \param sign_header_policy sign header policy
 * \return callable sign service
 */
SignService straight_sign_serviceV3(CertificateProvider& certificate_provider, Backend& backend, SignHeaderPolicy& sign_header_policy);

/**
 * SignService deferring actually signature calculation using EcdsaSignatureFuture
 * \param rt runtime
 * \param cert certificate provider
 * \param backend cryptographic backend
 * \param sign_header_policy sign header policy
 * \return callable sign service
 */
SignService deferred_sign_serviceV3(CertificateProvider& certificate_provider, Backend& backend, SignHeaderPolicy& sign_header_policy);

/**
 * SignService without real cryptography but dummy signature
 * \param rt runtime for appropriate generation time
 * \param si signer info attached to header fields of secured message
 * \return callable sign service
 */
SignService dummy_sign_serviceV3(const Runtime& rt, const SignerInfo& si);


} // namespace security
} // namespace vanetza

#endif /* SIGN_SERVICE_HPP_4MDQBSEF */
