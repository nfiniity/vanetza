#include "pki_security.hpp"

using namespace vanetza;

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

PkiSecurityContext::PkiSecurityContext(
    const Runtime &runtime,
    PositionProvider &positioning,
    const std::string &trust_store_path,
    const security::HashedId8 &rca_id,
    const security::HashedId8 &ea_id,
    const security::HashedId8 &aa_id,
    uint8_t num_authorization_tickets,
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
                          cert_cache, sign_header_policy, positioning)) {}

security::EncapConfirm
PkiSecurityContext::encapsulate_packet(security::EncapRequest &&request) {
    return delegating_entity.encapsulate_packet(std::move(request));
}

security::DecapConfirm
PkiSecurityContext::decapsulate_packet(security::DecapRequest&& request)
{
    return delegating_entity.decapsulate_packet(std::move(request));
}
