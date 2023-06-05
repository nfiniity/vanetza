#include <gtest/gtest.h>
#include <vanetza/pki/enrolment_certificates.hpp>
#include <vanetza/common/its_aid.hpp>

TEST(EnrolmentCertificates, BuildInnerEcRequest)
{
    std::string its_id("my_canonical_id");
    vanetza::security::openssl::EvpKey verification_key("prime256v1");

    // PSID/SSP for CA
    vanetza::asn1::PsidSsp ca_psid_ssp;
    ca_psid_ssp->psid = vanetza::aid::CA;
    ca_psid_ssp->ssp = vanetza::asn1::allocate<ServiceSpecificPermissions_t>();
    ca_psid_ssp->ssp->present = ServiceSpecificPermissions_PR_bitmapSsp;
    OCTET_STRING_fromBuf(&ca_psid_ssp->ssp->choice.bitmapSsp, "\x01\xff\xfc", 3);

    // PSID/SSP for DEN
    vanetza::asn1::PsidSsp den_psid_ssp;
    den_psid_ssp->psid = vanetza::aid::DEN;
    den_psid_ssp->ssp = vanetza::asn1::allocate<ServiceSpecificPermissions_t>();
    den_psid_ssp->ssp->present = ServiceSpecificPermissions_PR_bitmapSsp;
    OCTET_STRING_fromBuf(&den_psid_ssp->ssp->choice.bitmapSsp, "\x01\xff\xff\xff", 4);

    // PSID/SSP for GN_MGMT
    vanetza::asn1::PsidSsp gn_mgmt_psid_ssp;
    gn_mgmt_psid_ssp->psid = vanetza::aid::GN_MGMT;

    // Put all PSID/SSP pairs into a list
    vanetza::asn1::SequenceOfPsidSsp psid_ssp_list;
    ASN_SEQUENCE_ADD(&psid_ssp_list->list, vanetza::asn1::copy(asn_DEF_PsidSsp, &(*ca_psid_ssp)));
    ASN_SEQUENCE_ADD(&psid_ssp_list->list, vanetza::asn1::copy(asn_DEF_PsidSsp, &(*den_psid_ssp)));
    ASN_SEQUENCE_ADD(&psid_ssp_list->list, vanetza::asn1::copy(asn_DEF_PsidSsp, &(*gn_mgmt_psid_ssp)));

    // Build InnerEcRequest
    vanetza::asn1::InnerEcRequest inner_ec_request(
        vanetza::pki::build_inner_ec_request(its_id, verification_key, psid_ssp_list));

    ASSERT_TRUE(inner_ec_request.validate());
    xer_fprint(stdout, &asn_DEF_InnerEcRequest, &(*inner_ec_request));
}
