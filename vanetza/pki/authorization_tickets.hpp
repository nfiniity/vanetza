#ifndef AUTHORIZATION_TICKETS_HPP_LCX45A3G
#define AUTHORIZATION_TICKETS_HPP_LCX45A3G

#include <boost/optional.hpp>
#include <vanetza/asn1/shared_at_request.hpp>
#include <vanetza/asn1/psid_ssp.hpp>
#include <vanetza/asn1/ec_signature.hpp>
#include <vanetza/asn1/etsi_ts_102_941_data.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/encrypt_service.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/security_entity.hpp>

namespace vanetza {

namespace pki {

/*
 * Build an Authorization Ticket Request
 * as described in ETSI TS 102 941 V1.4.1 Section 6.2.3.3.1
 * \param at_verification_key new AT public key
 * \param ec_provider certificate provider for currently active enrolment certificate
 * \param ea_certificate EA certificate
 * \param aa_certificate AA certificate
 * \param psid_ssp_list list of PSID/SSP pairs
 */
security::EncryptConfirm
build_at_request(const security::openssl::EvpKey &at_verification_key,
                 security::CertificateProvider &ec_provider,
                 const security::CertificateV3 &ea_certificate,
                 const security::CertificateV3 &aa_certificate,
                 const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list = boost::none,
                 const std::string &at_verification_key_curve_name = "prime256v1");

asn1::SharedAtRequest build_shared_at_request(security::CertificateProvider &ec_provider,
                                              const std::array<uint8_t, 16> &key_tag,
                                              const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list);

void set_psid_ssps(asn1::SharedAtRequest& shared_at_request, const asn1::SequenceOfPsidSsp& psid_ssp_list);

asn1::EcSignature
build_ec_signature(asn1::SharedAtRequest shared_at_request,
                   security::CertificateProvider &ec_provider,
                   const security::CertificateV3 &ea_certificate,
                   security::BackendOpenSsl &backend);

asn1::EtsiTs102941Data
build_inner_at_request_wrapped(asn1::EcSignature &ec_signature,
                               asn1::SharedAtRequest &shared_at_request,
                               asn1::PublicVerificationKey &at_public_verification_key,
                               const ByteBuffer &hmac_key);

security::EncryptConfirm
sign_and_encrypt_inner_at_request_wrapped(asn1::EtsiTs102941Data &inner_at_request_wrapped,
                                          security::CertificateProvider &at_verification_key_provider,
                                          const security::CertificateV3 &aa_certificate,
                                          security::BackendOpenSsl &backend);

asn1::EtsiTs103097Certificate
decode_at_response(const security::SecuredMessageV3 &at_response,
                   const std::array<uint8_t, 16> &session_key,
                   security::SecurityEntity &security_entity);

} // namespace pki

} // namespace vanetza

#endif /* AUTHORIZATION_TICKETS_HPP_LCX45A3G */
