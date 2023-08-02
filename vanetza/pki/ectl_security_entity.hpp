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

// Example for manual PSID/SSP list creation
asn1::SequenceOfPsidSsp psid_ssp_list_example_manual();

// Example for PSID/SSP list creation from XML
asn1::SequenceOfPsidSsp psid_ssp_list_example_xml();

/*
 * Convert a hex string to a HashedId8
 * \param hex_string hex string with 16 characters
 */
security::HashedId8 hashed_id_from_hex_string(const std::string &hex_string);

class EctlSecurityEntity : public security::SecurityEntity
{
private:
    security::BackendOpenSsl backend;

    pki::CurlWrapper curl;
    pki::EctlPaths paths;
    security::CertificateCache cert_cache;
    pki::EctlTrustStore trust_store;
    pki::EnrolmentCertificateProvider ec_provider;
    pki::AuthorizationTicketProvider at_provider;
    security::DefaultSignHeaderPolicy sign_header_policy;
    security::DefaultCertificateValidator cert_validator;
    security::DelegatingSecurityEntity delegating_entity;

public:
    /**
     * ECTL PKI Security Context.
     * If the station is already enrolled, put the EC and key in
     * trust_store_path/ec/ec_cert.oer and trust_store_path/ec/ec_key.der.
     * Otherwise supply canonical_id and the canonical key in trust_store_path/reg/reg_key.der.
     * For details on the lifecycle, see ETSI TS 102 941 V1.4.1.
     * See functions above for id and psid_ssp_list creation.
     * \param runtime runtime
     * \param positioning position provider
     * \param trust_store_path path to trust store (with trailing slash)
     * \param rca_id id of root CA
     * \param ea_id id of enrolment authority
     * \param aa_id id of authorization authority
     * \param num_authorization_tickets number of authorization tickets to store
     * \param access_id_change_callback callback for access layer id change
     * \param psid_ssp_list list of PSID/SSP pairs (optional)
     * \param canonical_id canonical id (optional)
     */
    EctlSecurityEntity(
        Runtime &runtime,
        PositionProvider &positioning,
        const std::string &trust_store_path,
        const security::HashedId8 &rca_id,
        const security::HashedId8 &ea_id,
        const security::HashedId8 &aa_id,
        uint8_t num_authorization_tickets,
        security::IdChangeCallback &&access_id_change_callback,
        const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list,
        const boost::optional<std::string> &canonical_id);


    security::EncapConfirm
    encapsulate_packet(security::EncapRequest &&request) override;

    security::DecapConfirm
    decapsulate_packet(security::DecapRequest &&request) override;
};

} // namespace pki

} // namespace vanetza

#endif /* ECTL_SECURITY_ENITY_HPP_IIO34CX1 */
