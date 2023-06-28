#ifndef ENROLMENT_CERTIFICATES_HPP_0XJXZJZL
#define ENROLMENT_CERTIFICATES_HPP_0XJXZJZL

#include <boost/optional.hpp>
#include <vanetza/asn1/inner_ec_request.hpp>
#include <vanetza/asn1/psid_ssp.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/encrypt_service.hpp>

namespace vanetza {

namespace pki {

/*
 * Build an Enrolment Certificate Request
 * as described in ETSI TS 102 941 V1.4.1 Section 6.2.3.2.1
 * \param its_id canonical id for initial enrolment or HashedId8 of current EC for re-enrolment
 * \param verification_key new EC public key
 * \param active_certificate_provider certificate provider for current EC
 * \param psid_ssp_list list of PSID/SSP pairs
*/
security::EncryptConfirm
build_enrolment_request(const std::string &its_id,
                       const security::openssl::EvpKey &verification_key,
                       security::CertificateProvider& active_certificate_provider,
                       const security::CertificateV3& target_certificate,
                       const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list);

// Overload for initial enrolment with canonical key
security::EncryptConfirm
build_enrolment_request(const std::string &its_id,
                       const security::openssl::EvpKey &verification_key,
                       const security::openssl::EvpKey &canonical_key,
                       const security::CertificateV3& target_certificate,
                       const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list);

asn1::InnerEcRequest
build_inner_ec_request(const std::string &its_id,
                       const security::openssl::EvpKey &verification_key,
                       const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list = boost::none);

void set_public_verification_key(asn1::InnerEcRequest& inner_ec_request, const security::openssl::EvpKey& verification_key);

void set_certificate_subject_attributes(asn1::InnerEcRequest& inner_ec_request, const std::string& its_id);

void set_psid_ssps(asn1::InnerEcRequest& inner_ec_request, const asn1::SequenceOfPsidSsp& psid_ssp_list);

security::SecuredMessageV3
sign_ec_request_data(ByteBufferConvertible &&request_data,
                     security::CertificateProvider &certificate_provider,
                     security::PayloadTypeV3 request_data_type);

security::SecuredMessageV3
sign_inner_ec_request(asn1::InnerEcRequest &&inner_ec_request,
                      const security::openssl::EvpKey &verification_key);

security::EncryptConfirm
encrypt_ec_request(asn1::EtsiTs103097Data &&ec_request, const security::CertificateV3 &target_certificate);

}

}

#endif /* ENROLMENT_CERTIFICATES_HPP_0XJXZJZL */
