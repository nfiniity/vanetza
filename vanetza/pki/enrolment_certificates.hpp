#ifndef ENROLMENT_CERTIFICATES_HPP_0XJXZJZL
#define ENROLMENT_CERTIFICATES_HPP_0XJXZJZL

#include <vanetza/asn1/inner_ec_request.hpp>
#include <vanetza/security/openssl_wrapper.hpp>

namespace vanetza {

namespace pki {

/*
 * Build an InnerEcRequest
 * \param its_id canonical id for initial enrolment or HashedId8 of current EC for re-enrolment
 * \param psid_ssp_list list of PSID/SSP pairs
 * \param verification_key new EC public key
*/
asn1::InnerEcRequest
build_inner_ec_request(const std::string &its_id,
                       const std::vector<ItsAid> &psid_ssp_list,
                       const security::openssl::EvpKey &verification_key);

void set_public_verification_key(asn1::InnerEcRequest& inner_ec_request, const security::openssl::EvpKey& verification_key);

void set_certificate_subject_attributes(asn1::InnerEcRequest& inner_ec_request, const std::string& its_id);

void set_psid_ssps(asn1::InnerEcRequest& inner_ec_request, const std::vector<ItsAid>& psid_ssp_list);
}

}

#endif /* ENROLMENT_CERTIFICATES_HPP_0XJXZJZL */
