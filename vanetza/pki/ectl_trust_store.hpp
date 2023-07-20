#ifndef ECTL_VANETZA_TRUST_STORE_HPP_82F21CCI
#define ECTL_VANETZA_TRUST_STORE_HPP_82F21CCI

#include <vanetza/pki/curl_wrapper.hpp>
#include <vanetza/security/trust_store.hpp>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/asn1/to_be_signed_tlm_ctl.hpp>
#include <curl/curl.h>
#include <set>
#include <map>

namespace vanetza
{
namespace pki
{

struct EctlPaths {
    /*
     * Construct ECTL paths
     * \param base_path Base path for ECTL storage (with trailing slash)
     */
    explicit EctlPaths(const std::string &base_path);

    void create_directories() const;

    // TLM cert and ECTL cache directory (base_path/ctl/)
    std::string ctl;
    // TLM cert (base_path/ctl/tlm_cert.oer)
    std::string tlm_cert;
    // ECTL cache (base_path/ctl/ectl.oer)
    std::string ectl;
    // RCA CRLs cache directory (base_path/crl/)
    std::string crl;
    // Registration key directory (base_path/reg/)
    std::string reg;
    // Registration key (base_path/reg/reg_key.der)
    std::string reg_key;
    // Enrollment certificate and key directory
    std::string ec;
    // Authorization tickets and keys directory
    std::string at;
};

struct RcaMetadata
{
    std::string dc_url;
    std::set<security::HashedId8> revoked_ids;
};

static const std::string L0_CPOC_URL = "https://cpoc.jrc.ec.europa.eu/L0/";

class EctlTrustStore : public security::TrustStore
{
public:
    /*
     * A trust store with root certificates from the ECTL
     * \param paths ECTL paths
     * \param runtime Runtime instance
     * \param cpoc_url URL of CPOC server (with trailing slash)
     */
    EctlTrustStore(const EctlPaths &paths,
                   const Runtime &runtime,
                   security::Backend &backend,
                   const std::string &cpoc_url = L0_CPOC_URL);
    ~EctlTrustStore() override = default;

    bool is_revoked(const security::HashedId8 &issuer_id,
                    const security::HashedId8 &cert_id) const override;

  private:
    /*
     * Load cached TLM certificate and check if update is required
     * \return true if TLM certificate was loaded or updated
     */
    bool refresh_tlm_cert();
    void refresh_ectl();
    void set_next_tlm_cert_update();
    Clock::time_point calc_next_ectl_update(const asn1::ToBeSignedTlmCtl &ectl) const;
    boost::optional<asn1::ToBeSignedTlmCtl> parse_ectl(const ByteBuffer &buffer) const;
    bool load_ectl(const asn1::ToBeSignedTlmCtl &ectl, const security::Sha384Digest &buffer_hash);
    void recover_failed_ectl_update(
        const boost::optional<asn1::ToBeSignedTlmCtl> &cached_ectl,
        const boost::optional<security::Sha384Digest> &buffer_hash);

    const EctlPaths &paths;
    const Runtime &runtime;
    security::Backend &backend;
    std::string cpoc_url;

    CurlWrapper curl;
    boost::optional<security::CertificateV3> tlm_cert;
    // Hash of ECTL buffer the store was loaded from
    boost::optional<security::Sha384Digest> ectl_buffer_hash;
    Clock::time_point next_tlm_cert_update;
    Clock::time_point next_ectl_update;
    std::map<security::HashedId8, RcaMetadata> rca_metadata_map;
};

} // namespace pki
} // namespace vanetza

#endif /* ECTL_VANETZA_TRUST_STORE_HPP_82F21CCI */
