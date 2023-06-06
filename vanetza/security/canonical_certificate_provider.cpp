#include <vanetza/security/canonical_certificate_provider.hpp>

namespace vanetza
{
namespace security
{

CanonicalCertificateProvider::CanonicalCertificateProvider(const ecdsa256::PrivateKey& canonical_key) :
    canonical_key(canonical_key)
{
}

int CanonicalCertificateProvider::version()
{
    return 3;
}

const ecdsa256::PrivateKey& CanonicalCertificateProvider::own_private_key()
{
    return canonical_key;
}

std::list<CertificateVariant> CanonicalCertificateProvider::own_chain()
{
    return std::list<CertificateVariant> {};
}

const CertificateVariant& CanonicalCertificateProvider::own_certificate()
{
    return cert;
}


} // namespace security
} // namespace vanetza
