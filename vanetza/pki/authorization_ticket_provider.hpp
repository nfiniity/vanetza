#ifndef AUTHORIZATION_TICKET_PROVIDER_HPP_OO1CYSK7
#define AUTHORIZATION_TICKET_PROVIDER_HPP_OO1CYSK7

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

class AuthorizationTicketProvider : public security::CertificateProvider
{
public:
    /**
     * Create enrolment certificate provider
     * \param num_authorization_tickets number of authorization tickets to store
     * \param ec_provider provider for currently active EC
     * \param ea_certificate certificate of EA
     * \param aa_certificate certificate of AA
     * \param backend Backend
     * \param runtime used for signatures
     * \param curl used for HTTP requests
     * \param ectl_paths paths for AT storage
     * \param psid_ssp_list list of PSID/SSP pairs
     */
    explicit AuthorizationTicketProvider(uint8_t num_authorization_tickets,
                                         security::CertificateProvider& ec_provider,
                                         const SubCertificateV3& ea_certificate,
                                         const SubCertificateV3& aa_certificate,
                                         security::BackendOpenSsl& backend,
                                         Runtime &runtime,
                                         CurlWrapper& curl,
                                         const EctlPaths& ectl_paths,
                                         const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list);


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
    void reset_switch_timer(const Clock::time_point &next_switch);

    bool refresh_authorization_ticket();
    void set_authorization_ticket(
        uint8_t index, const security::CertificateV3 &certificate,
        const security::openssl::EvpKey &private_key);
    void save_new_authorization_ticket(
        uint8_t index, const security::CertificateV3 &certificate,
        const security::openssl::EvpKey &private_key) const;

    uint8_t get_next_index() const;
    void set_next_switch();

    bool authorize(uint8_t new_index);

    boost::optional<security::CertificateV3>
    run_authorization_request(const security::EncryptConfirm &authorization_request);

    uint8_t num_authorization_tickets;
    security::CertificateProvider& ec_provider;
    SubCertificateV3 ea_certificate;
    SubCertificateV3 aa_certificate;
    security::BackendOpenSsl& backend;
    Runtime &runtime;
    CurlWrapper& curl;
    const EctlPaths& ectl_paths;
    boost::optional<asn1::SequenceOfPsidSsp> psid_ssp_list;
    boost::optional<std::string> canonical_id;

    boost::optional<security::CertificateVariant> authorization_ticket;
    boost::optional<security::ecdsa256::PrivateKey> authorization_ticket_key;
    uint8_t current_index = 255;
};


} // namespace pki
} // namespace vanetza

#endif /* AUTHORIZATION_TICKET_PROVIDER_HPP_OO1CYSK7 */
