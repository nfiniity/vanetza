#ifndef PKI_SECURITY_HPP_IIO34CX1
#define PKI_SECURITY_HPP_IIO34CX1

#include <vanetza/pki/enrolment_certificate_provider.hpp>
#include <vanetza/pki/authorization_ticket_provider.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/sign_header_policy.hpp>

class PkiSecurityContext : public vanetza::security::SecurityEntity
{
public:
    vanetza::security::BackendOpenSsl backend;

    vanetza::pki::CurlWrapper curl;
    vanetza::pki::EctlPaths paths;
    vanetza::pki::EctlTrustStore trust_store;
    vanetza::pki::EnrolmentCertificateProvider ec_provider;
    vanetza::pki::AuthorizationTicketProvider at_provider;
    vanetza::security::DefaultSignHeaderPolicy sign_header_policy;
    vanetza::security::CertificateCache cert_cache;
    vanetza::security::DefaultCertificateValidator cert_validator;
    vanetza::security::DelegatingSecurityEntity delegating_entity;

    PkiSecurityContext(
        const vanetza::Runtime &runtime,
        vanetza::PositionProvider &positioning,
        const std::string &trust_store_path,
        const vanetza::security::HashedId8 &rca_id,
        const vanetza::security::HashedId8 &ea_id,
        const vanetza::security::HashedId8 &aa_id,
        uint8_t num_authorization_tickets,
        const boost::optional<vanetza::asn1::SequenceOfPsidSsp> &psid_ssp_list,
        const boost::optional<std::string> &canonical_id);


    vanetza::security::EncapConfirm
    encapsulate_packet(vanetza::security::EncapRequest &&request) override;

    vanetza::security::DecapConfirm
    decapsulate_packet(vanetza::security::DecapRequest &&request) override;
};


#endif /* PKI_SECURITY_HPP_IIO34CX1 */

