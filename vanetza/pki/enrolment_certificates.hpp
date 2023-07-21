#ifndef ENROLMENT_CERTIFICATES_HPP_0XJXZJZL
#define ENROLMENT_CERTIFICATES_HPP_0XJXZJZL

#include <boost/optional.hpp>
#include <vanetza/asn1/inner_ec_request.hpp>
#include <vanetza/asn1/psid_ssp.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/encrypt_service.hpp>
#include <vanetza/security/security_entity.hpp>

namespace vanetza {

namespace pki {

/*
 * Build an Enrolment Certificate Request
 * as described in ETSI TS 102 941 V1.4.1 Section 6.2.3.2.1
 * \param its_id canonical id for initial enrolment or HashedId8 of current EC for re-enrolment
 * \param verification_key new EC public key
 * \param active_certificate_provider certificate provider for current EC or self-signed dummy
 * \param ea_certificate certificate of EA
 * \param runtime used for signature
 * \param psid_ssp_list list of PSID/SSP pairs
 * \param verification_key_curve_name name of curve used for new verification key
 * \return EncryptConfirm containing encrypted EC request and session key
*/
security::EncryptConfirm
build_enrolment_request(const ByteBuffer &its_id,
                        const security::openssl::EvpKey &verification_key,
                        security::CertificateProvider& active_certificate_provider,
                        const security::CertificateV3& ea_certificate,
                        const Runtime &runtime,
                        const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list = boost::none,
                        const std::string& verification_key_curve_name = "prime256v1");

asn1::InnerEcRequest
build_inner_ec_request(const ByteBuffer &its_id,
                       const security::openssl::EvpKey &verification_key,
                       const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list);

void set_public_verification_key(asn1::InnerEcRequest& inner_ec_request, const security::openssl::EvpKey& verification_key);

void set_psid_ssps(asn1::InnerEcRequest& inner_ec_request, const asn1::SequenceOfPsidSsp& psid_ssp_list);

security::SecuredMessageV3
sign_ec_request_data(ByteBufferConvertible &&request_data,
                     security::CertificateProvider &certificate_provider,
                     security::PayloadTypeV3 request_data_type,
                     const Runtime &runtime);

security::EncryptConfirm
encrypt_ec_request(asn1::EtsiTs103097Data &&ec_request, const security::CertificateV3 &ea_certificate);

/*
 * Decrypt, verify and parse an Enrolment Response
 * \param ec_response encrypted EC response message
 * \param session_key session key used for encryption
 * \param ea_certificate certificate of EA
 * \param runtime used for signature verification
 * \return Enrolment certificate
*/
security::CertificateV3
decode_ec_response(const security::SecuredMessageV3 &ec_response,
                   const std::array<uint8_t, 16> &session_key,
                   const security::CertificateV3 &ea_certificate,
                   const Runtime &runtime);
}

}

#endif /* ENROLMENT_CERTIFICATES_HPP_0XJXZJZL */
