#ifndef ECTL_VANETZA_TRUST_STORE_HPP_82F21CCI
#define ECTL_VANETZA_TRUST_STORE_HPP_82F21CCI

#include <vanetza/pki/curl_wrapper.hpp>
#include <vanetza/security/trust_store.hpp>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/asn1/ctl.hpp>
#include <vanetza/asn1/crl.hpp>
#include <vanetza/asn1/etsi_ts_102_941_data.hpp>
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
    // RCA cache directory (base_path/rca/)
    std::string rca;
    // Registration key directory (base_path/reg/)
    std::string reg;
    // Registration key (base_path/reg/reg_key.der)
    std::string reg_key;
    // Enrollment certificate and key directory
    std::string ec;
    // Enrollment certificate (base_path/ec/ec_cert.oer)
    std::string ec_cert;
    // Enrollment certificate key (base_path/ec/ec_key.der)
    std::string ec_key;
    // Authorization tickets and keys directory
    std::string at;

    // Authorization ticket (base_path/at/{index}/at_cert.oer)
    std::string at_cert(uint8_t index) const;
    // Authorization ticket key (base_path/at/{index}/at_key.der)
    std::string at_key(uint8_t index) const;
    // RCA CTL (base_path/rca/{rca_id}/ctl.oer)
    std::string rca_ctl(const std::string &rca_id) const;
    // RCA CRL (base_path/rca/{rca_id}/crl.oer)
    std::string rca_crl(const std::string &rca_id) const;
};

enum class SubCaType
{
    EA,
    AA
};

struct SubCertificateV3
{
    // Certificate
    security::CertificateV3 certificate;
    // URL of AA access point or EA ITS access point
    boost::optional<std::string> access_point_url;
    // Type of sub CA
    SubCaType type;
};

struct RcaMetadata
{
    std::string dc_url;

    boost::optional<std::map<security::HashedId8, SubCertificateV3>> subcerts;
    Clock::time_point next_ctl_update;

    boost::optional<std::set<security::HashedId8>> revoked_subcerts;
    Clock::time_point next_crl_update;
};

static const std::string L0_CPOC_URL = "https://cpoc.jrc.ec.europa.eu/L0/";

class EctlTrustStore : public security::TrustStore
{
public:
    /*
     * A trust store with root certificates from the ECTL
     * \param paths ECTL paths
     * \param runtime Runtime instance
     * \param curl Curl Wrapper
     * \param backend Security backend
     * \param cert_cache Certificate cache
     * \param cpoc_url URL of CPOC server (with trailing slash)
     */
    EctlTrustStore(const EctlPaths &paths,
                   const Runtime &runtime,
                   CurlWrapper& curl,
                   security::Backend &backend,
                   security::CertificateCache &cert_cache,
                   const std::string &cpoc_url = L0_CPOC_URL);
    ~EctlTrustStore() override = default;

    /**
     * Lookup certificates based on the passed HashedId8.
     *
     * \param id hash identifier of the certificate
     * \return all stored certificates matching the passed identifier
     */
    std::list<security::CertificateVariant>
    lookup(const security::HashedId8 &id) override;

    /*
     * Check if a subcertificate is revoked
     * \param rca_id issuer ID of subcertificate
     * \param subcert_id certificate ID of subcertificate
     */
    bool is_revoked(const security::HashedId8 &rca_id,
                    const security::HashedId8 &subcert_id) override;

    /*
     * Request a subcertificate from a RCA directly
     * \param rca_id issuer ID of subcertificate
     * \param subcert_id certificate ID of subcertificate
     */
    boost::optional<SubCertificateV3>
    get_subcert(const security::HashedId8 &rca_id,
                const security::HashedId8 &subcert_id);

  private:
    /*
     * Load cached TLM certificate and check if update is required
     * \return true if TLM certificate was loaded or updated
     */
    bool refresh_tlm_cert();
    void set_next_tlm_cert_update();

    void refresh_ectl();
    bool load_ectl(const asn1::ToBeSignedTlmCtl &ectl, const security::Sha384Digest &buffer_hash);
    boost::optional<asn1::ToBeSignedTlmCtl> parse_ectl(const ByteBuffer &buffer);
    Clock::time_point calc_next_ectl_update(const asn1::ToBeSignedTlmCtl &ectl) const;
    void recover_failed_ectl_update(
        const boost::optional<asn1::ToBeSignedTlmCtl> &cached_ectl,
        const boost::optional<security::Sha384Digest> &buffer_hash);

    void refresh_rca_ctl(const security::HashedId8 &id, RcaMetadata &metadata);
    boost::optional<asn1::ToBeSignedRcaCtl>
    parse_rca_ctl(const ByteBuffer &buffer, const security::HashedId8 &rca_id);
    bool load_rca_ctl(const asn1::ToBeSignedRcaCtl &rca_ctl, RcaMetadata &metadata) const;

    void refresh_rca_crl(const security::HashedId8 &id, RcaMetadata &metadata);
    boost::optional<asn1::ToBeSignedCrl>
    parse_rca_crl(const ByteBuffer &buffer, const security::HashedId8 &rca_id);
    bool load_rca_crl(const asn1::ToBeSignedCrl &rca_crl, RcaMetadata &metadata) const;

    boost::optional<asn1::EtsiTs102941Data>
    parse_rca_etsi_ts_102_941_data(const ByteBuffer &buffer,
                                   const security::HashedId8 &rca_id);

    boost::optional<asn1::EtsiTs102941Data> parse_etsi_ts_102_941_data(
        const ByteBuffer &message_buffer,
        const security::HashedId8 &expected_signer_id,
        security::CertificateValidator &cert_validator);

    const EctlPaths &paths;
    const Runtime &runtime;
    CurlWrapper& curl;
    security::Backend &backend;
    security::CertificateCache &cert_cache;
    std::string cpoc_url;

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
