#include <vanetza/pki/ectl_security_entity.hpp>
#include <boost/algorithm/hex.hpp>

namespace vanetza
{

namespace pki
{

security::DelegatingSecurityEntity
build_delegating_entity(const Runtime &runtime,
                        security::BackendOpenSsl &backend,
                        security::CertificateProvider &cert_provider,
                        security::CertificateValidator &cert_validator,
                        security::CertificateCache &cert_cache,
                        security::SignHeaderPolicy &sign_header_policy,
                        PositionProvider &positioning)
{
    security::SignService sign_service = straight_sign_serviceV3(cert_provider, backend, sign_header_policy);
    security::VerifyService verify_service = straight_verify_service(runtime, cert_provider, cert_validator,
            backend, cert_cache, sign_header_policy, positioning);
    return security::DelegatingSecurityEntity(std::move(sign_service), std::move(verify_service));
}

pki::EnrolmentCertificateProvider
build_ec_provider(pki::EctlTrustStore &trust_store,
                  const pki::EctlPaths &paths,
                  security::BackendOpenSsl &backend,
                  const Runtime &runtime,
                  pki::CurlWrapper &curl,
                  const security::HashedId8 &rca_id,
                  const security::HashedId8 &ea_id,
                  const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list,
                  const boost::optional<std::string> &canonical_id)
{
    auto ea_res = trust_store.get_subcert(rca_id, ea_id);
    assert(ea_res);
    assert(ea_res->type == pki::SubCaType::EA);

    return pki::EnrolmentCertificateProvider(
        *ea_res, backend, runtime, curl, paths, psid_ssp_list, canonical_id);
}

pki::AuthorizationTicketProvider
build_at_provider(pki::EctlTrustStore &trust_store,
                  const pki::EctlPaths &paths,
                  security::BackendOpenSsl &backend,
                  const Runtime &runtime,
                  pki::CurlWrapper &curl,
                  security::CertificateProvider &ec_provider,
                  const security::HashedId8 &rca_id,
                  const security::HashedId8 &ea_id,
                  const security::HashedId8 &aa_id,
                  uint8_t num_authorization_tickets,
                  const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list)
{
    auto ea_res = trust_store.get_subcert(rca_id, ea_id);
    assert(ea_res);
    assert(ea_res->type == pki::SubCaType::EA);

    auto aa_res = trust_store.get_subcert(rca_id, aa_id);
    assert(aa_res);
    assert(aa_res->type == pki::SubCaType::AA);

    return pki::AuthorizationTicketProvider(
        num_authorization_tickets, ec_provider, *ea_res, *aa_res,
        backend, runtime, curl, paths, psid_ssp_list);
}

EctlSecurityEntity::EctlSecurityEntity(
    const Runtime &runtime,
    PositionProvider &positioning,
    const std::string &trust_store_path,
    const security::HashedId8 &rca_id,
    const security::HashedId8 &ea_id,
    const security::HashedId8 &aa_id,
    uint8_t num_authorization_tickets,
    security::IdChangeCallback &&access_id_change_callback,
    const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list,
    const boost::optional<std::string> &canonical_id)
    : curl(runtime), paths(trust_store_path), trust_store(paths, runtime, curl, backend),
        ec_provider(build_ec_provider(trust_store, paths, backend, runtime,
                                    curl, rca_id, ea_id, psid_ssp_list,
                                    canonical_id)),
        at_provider(build_at_provider(trust_store, paths, backend, runtime,
                                    curl, ec_provider, rca_id, ea_id, aa_id,
                                    num_authorization_tickets, psid_ssp_list)),
        sign_header_policy(runtime, positioning), cert_cache(runtime),
        cert_validator(backend, cert_cache, trust_store),
        delegating_entity(build_delegating_entity(runtime, backend, at_provider, cert_validator,
                          cert_cache, sign_header_policy, positioning))
{
    register_id_change_callback(std::move(access_id_change_callback));
}

security::EncapConfirm
EctlSecurityEntity::encapsulate_packet(security::EncapRequest &&request) {
    return delegating_entity.encapsulate_packet(std::move(request));
}

security::DecapConfirm
EctlSecurityEntity::decapsulate_packet(security::DecapRequest&& request)
{
    return delegating_entity.decapsulate_packet(std::move(request));
}

asn1::SequenceOfPsidSsp psid_ssp_list_example_manual()
{
    // Example code for PSID/SSP list creation

    // PSID/SSP for CA
    asn1::PsidSsp ca_psid_ssp;
    ca_psid_ssp->psid = aid::CA;
    ca_psid_ssp->ssp = asn1::allocate<ServiceSpecificPermissions_t>();
    ca_psid_ssp->ssp->present = ServiceSpecificPermissions_PR_bitmapSsp;
    OCTET_STRING_fromBuf(&ca_psid_ssp->ssp->choice.bitmapSsp, "\x01\xff\xfc", 3);

    // PSID/SSP for DEN
    asn1::PsidSsp den_psid_ssp;
    den_psid_ssp->psid = aid::DEN;
    den_psid_ssp->ssp = asn1::allocate<ServiceSpecificPermissions_t>();
    den_psid_ssp->ssp->present = ServiceSpecificPermissions_PR_bitmapSsp;
    OCTET_STRING_fromBuf(&den_psid_ssp->ssp->choice.bitmapSsp, "\x01\xff\xff\xff", 4);

    // PSID/SSP for GN_MGMT
    asn1::PsidSsp gn_mgmt_psid_ssp;
    gn_mgmt_psid_ssp->psid = aid::GN_MGMT;

    // Put all PSID/SSP pairs into a list
    asn1::SequenceOfPsidSsp psid_ssp_list;
    ASN_SEQUENCE_ADD(&psid_ssp_list->list,
                     asn1::copy(asn_DEF_PsidSsp, &(*ca_psid_ssp)));
    ASN_SEQUENCE_ADD(&psid_ssp_list->list,
                     asn1::copy(asn_DEF_PsidSsp, &(*den_psid_ssp)));
    ASN_SEQUENCE_ADD(&psid_ssp_list->list,
                     asn1::copy(asn_DEF_PsidSsp, &(*gn_mgmt_psid_ssp)));

    xer_fprint(stdout, &asn_DEF_SequenceOfPsidSsp, &(*psid_ssp_list));

    return psid_ssp_list;
}

// Or read from file
const std::string psid_ssp_xml =
R"(<SequenceOfPsidSsp>
    <PsidSsp>
        <psid>36</psid>
        <ssp>
            <bitmapSsp>01 FF FC</bitmapSsp>
        </ssp>
    </PsidSsp>
    <PsidSsp>
        <psid>37</psid>
        <ssp>
            <bitmapSsp>01 FF FF FF</bitmapSsp>
        </ssp>
    </PsidSsp>
    <PsidSsp>
        <psid>141</psid>
    </PsidSsp>
</SequenceOfPsidSsp>)";

asn1::SequenceOfPsidSsp psid_ssp_list_example_xml()
{
    ByteBuffer buffer(psid_ssp_xml.begin(), psid_ssp_xml.end());
    asn1::SequenceOfPsidSspXml psid_ssp_list_xml;
    psid_ssp_list_xml.decode(buffer);

    // Swap into OER representation
    asn1::SequenceOfPsidSsp psid_ssp_list;
    psid_ssp_list.swap(psid_ssp_list_xml);
    return psid_ssp_list;
}

security::HashedId8 hashed_id_from_hex_string(const std::string &hex_string)
{
    assert(hex_string.size() == 16);
    security::HashedId8 hashed_id;
    boost::algorithm::unhex(hex_string, hashed_id.data());
    return hashed_id;
}

} // namespace pki

} // namespace vanetza
