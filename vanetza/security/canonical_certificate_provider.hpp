#ifndef CANONICAL_CERTIFICATE_PROVIDER_HPP_ZJ76GU3X
#define CANONICAL_CERTIFICATE_PROVIDER_HPP_ZJ76GU3X

#include <vanetza/security/certificate_provider.hpp>

namespace vanetza
{
namespace security
{

/**
 * A certificate provider that uses a canonical key with an empty certificate chain
 */
class CanonicalCertificateProvider : public CertificateProvider
{
public:
    /**
     * Create canonical certificate provider with empty chain
     * \param authorization_ticket
     * \param ticket_key private key of given authorization ticket
     */
    CanonicalCertificateProvider(const ecdsa256::PrivateKey& canonical_key);

    int version() override;
    /**
     * Get own certificate to use for signing
     * \return own certificate
     */
    const CertificateVariant& own_certificate() override;

    /**
     * Get own certificate chain, excluding the leaf certificate and root CA
     * \return own certificate chain
     */
    std::list<CertificateVariant> own_chain() override;

    /**
     * Get private key associated with own certificate
     * \return private key
     */
    const ecdsa256::PrivateKey& own_private_key() override;

private:
    ecdsa256::PrivateKey canonical_key;
    CertificateVariant cert {CertificateV3()};
};


} // namespace security
} // namespace vanetza

#endif /* CANONICAL_CERTIFICATE_PROVIDER_HPP_ZJ76GU3X */
