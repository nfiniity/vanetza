#ifndef ECTL_SECURITY_ENITY_HPP_IIO34CX1
#define ECTL_SECURITY_ENITY_HPP_IIO34CX1

#include <vanetza/pki/enrolment_certificate_provider.hpp>
#include <vanetza/pki/authorization_ticket_provider.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/sign_header_policy.hpp>

namespace vanetza
{

namespace pki
{

class EctlSecurityEntity : public security::SecurityEntity
{
private:
    security::BackendOpenSsl backend;

    pki::CurlWrapper curl;
    pki::EctlPaths paths;
    pki::EctlTrustStore trust_store;
    pki::EnrolmentCertificateProvider ec_provider;
    pki::AuthorizationTicketProvider at_provider;
    security::DefaultSignHeaderPolicy sign_header_policy;
    security::CertificateCache cert_cache;
    security::DefaultCertificateValidator cert_validator;
    security::DelegatingSecurityEntity delegating_entity;

public:
    /**
     * ECTL PKI Security Context
     * \param runtime runtime
     * \param positioning position provider
     * \param trust_store_path path to trust store
     * \param rca_id id of root CA
     * \param ea_id id of enrolment authority
     * \param aa_id id of authorization authority
     * \param num_authorization_tickets number of authorization tickets to store
     * \param psid_ssp_list list of PSID/SSP pairs (optional)
     * \param canonical_id canonical id (optional)
     */
    EctlSecurityEntity(
        const Runtime &runtime,
        PositionProvider &positioning,
        const std::string &trust_store_path,
        const security::HashedId8 &rca_id,
        const security::HashedId8 &ea_id,
        const security::HashedId8 &aa_id,
        uint8_t num_authorization_tickets,
        const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list,
        const boost::optional<std::string> &canonical_id);


    security::EncapConfirm
    encapsulate_packet(security::EncapRequest &&request) override;

    security::DecapConfirm
    decapsulate_packet(security::DecapRequest &&request) override;
};

vanetza::asn1::SequenceOfPsidSsp get_psid_ssp_list();

} // namespace pki

} // namespace vanetza

#endif /* ECTL_SECURITY_ENITY_HPP_IIO34CX1 */
