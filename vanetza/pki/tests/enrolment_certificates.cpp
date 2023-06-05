#include <gtest/gtest.h>
#include <vanetza/pki/enrolment_certificates.hpp>
#include <vanetza/common/its_aid.hpp>

TEST(EnrolmentCertificates, BuildInnerEcRequest)
{
    std::string its_id("my_canonical_id");
    vanetza::security::openssl::EvpKey verification_key("prime256v1");
    std::vector<vanetza::ItsAid> psid_ssp_list = { vanetza::aid::CA, vanetza::aid::DEN, vanetza::aid::GN_MGMT };

    vanetza::asn1::InnerEcRequest inner_ec_request(
        vanetza::pki::build_inner_ec_request(its_id, psid_ssp_list,
                                             verification_key));
    ASSERT_TRUE(inner_ec_request.validate());
    xer_fprint(stdout, &asn_DEF_InnerEcRequest, &(*inner_ec_request));
}
