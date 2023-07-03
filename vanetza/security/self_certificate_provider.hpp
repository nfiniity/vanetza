#ifndef SELF_CERTIFICATE_PROVIDER_HPP_ZJ76GU3X
#define SELF_CERTIFICATE_PROVIDER_HPP_ZJ76GU3X

#include <vanetza/security/certificate_provider.hpp>

namespace vanetza
{
namespace security
{

/**
 * A certificate provider that uses a key with an empty certificate chain
 * Used in EC and AT requests
 */
class SelfCertificateProvider : public CertificateProvider
{
public:
    /**
     * Create self certificate provider with empty chain
     * \param canonical_key private canonical key
     * \param curve_name name of elliptic curve
     */
  explicit SelfCertificateProvider(const ecdsa256::PrivateKey &canonical_key,
                                   const std::string &curve_name);

  int version() override;
  /**
   * Get certificate with issuer_identifier set to 0
   * \return own certificate
   */
  const CertificateVariant &own_certificate() override;

  /**
   * Get empty certificate chain
   * \return own certificate chain
   */
  std::list<CertificateVariant> own_chain() override;

  /**
   * Get private key associated with own certificate
   * \return private key
   */
  const ecdsa256::PrivateKey &own_private_key() override;

private:
    ecdsa256::PrivateKey canonical_key;
    CertificateVariant cert;
};


} // namespace security
} // namespace vanetza

#endif /* SELF_CERTIFICATE_PROVIDER_HPP_ZJ76GU3X */
