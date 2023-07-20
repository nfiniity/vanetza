#ifndef VANETZA_TRUST_STORE_HPP
#define VANETZA_TRUST_STORE_HPP

#include <vanetza/security/certificate.hpp>
#include <list>
#include <map>

namespace vanetza
{
namespace security
{

class TrustStore
{
public:
    TrustStore() = default;
    virtual ~TrustStore() = default;

    /**
     * Lookup certificates based on the passed HashedId8.
     *
     * \param id hash identifier of the certificate
     * \return all stored certificates matching the passed identifier
     */
    virtual std::list<CertificateVariant> lookup(const HashedId8& id);

    /**
     * Insert a certificate into store, i.e. consider it as trustworthy.
     * \param trusted_certificate a trustworthy certificate copied into TrustStore
     */
    void insert(const CertificateVariant& trusted_certificate);

    /*
     * Check if a certificate is revoked.
     * \param issuer_id issuer identifier of the root CA certificate
     * \param cert_id hash identifier of the subordinate EA/AA certificate
     * \return true if certificate is revoked, false otherwise
    */
    virtual bool is_revoked(const HashedId8& issuer_id, const HashedId8& cert_id) const
    {
        return false;
    }

protected:
    std::multimap<HashedId8, CertificateVariant> m_certificates;
};

} // namespace security
} // namespace vanetza

#endif /* VANETZA_TRUST_STORE_HPP */
