#include <vanetza/security/self_certificate_provider.hpp>

namespace vanetza
{
namespace security
{

SelfCertificateProvider::SelfCertificateProvider(const ecdsa256::PrivateKey& canonical_key) :
    canonical_key(canonical_key)
{
}

int SelfCertificateProvider::version()
{
    return 3;
}

const ecdsa256::PrivateKey& SelfCertificateProvider::own_private_key()
{
    return canonical_key;
}

std::list<CertificateVariant> SelfCertificateProvider::own_chain()
{
    return std::list<CertificateVariant> {};
}

const CertificateVariant& SelfCertificateProvider::own_certificate()
{
    return cert;
}


} // namespace security
} // namespace vanetza
