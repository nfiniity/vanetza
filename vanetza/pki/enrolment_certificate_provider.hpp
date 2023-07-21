#ifndef ENROLMENT_CERTIFICATE_PROVIDER_HPP_978BDA9L
#define ENROLMENT_CERTIFICATE_PROVIDER_HPP_978BDA9L

#include <vanetza/pki/ectl_trust_store.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/encrypt_service.hpp>
#include <vanetza/asn1/psid_ssp.hpp>

namespace vanetza
{
namespace pki
{

class EnrolmentCertificateProvider : public security::CertificateProvider
{
public:
    /**
     * Create enrolment certificate provider
     * \param ea_certificate certificate of EA
     * \param backend Backend
     * \param runtime used for signatures
     * \param curl used for HTTP requests
     * \param ectl_paths paths for EC storage
     * \param psid_ssp_list list of PSID/SSP pairs
     * \param canonical_id canonical id used for registration (place key according to EctlPaths)
     */
    explicit EnrolmentCertificateProvider(const SubCertificateV3& ea_certificate,
                                          security::BackendOpenSsl& backend,
                                          const Runtime &runtime,
                                          CurlWrapper& curl,
                                          const EctlPaths& ectl_paths,
                                          const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list,
                                          const boost::optional<std::string>& canonical_id);

    int version() override;
    /**
     * Get enrolment certificate to use for signing AT requests
     * \return enrolment certificate
     */
    const security::CertificateVariant& own_certificate() override;

    /**
     * Not needed
     * \return empty certificate chain
     */
    std::list<security::CertificateVariant> own_chain() override;

    /**
     * Get private key associated with enrolment certificate
     * \return private key
     */
    const security::ecdsa256::PrivateKey& own_private_key() override;

private:
    bool refresh_enrolment_certificate();
    void set_next_update();
    void set_new_enrolment_certificate(
        const security::CertificateV3 &certificate,
        const security::openssl::EvpKey &private_key);

    bool initial_enrol();
    bool re_enrol();

    boost::optional<security::CertificateV3>
    run_enrolment_request(const security::EncryptConfirm &request);

    SubCertificateV3 ea_certificate;
    security::BackendOpenSsl& backend;
    const Runtime &runtime;
    CurlWrapper& curl;
    const EctlPaths& ectl_paths;
    boost::optional<asn1::SequenceOfPsidSsp> psid_ssp_list;
    boost::optional<std::string> canonical_id;

    boost::optional<security::CertificateVariant> enrolment_certificate;
    boost::optional<security::ecdsa256::PrivateKey> enrolment_certificate_key;
    Clock::time_point next_update;
};


} // namespace pki
} // namespace vanetza

#endif /* ENROLMENT_CERTIFICATE_PROVIDER_HPP_978BDA9L */
