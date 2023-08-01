#include <vanetza/pki/ectl_trust_store.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/verify_service.hpp>
#include <vanetza/asn1/utils.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <fstream>

namespace vanetza
{
namespace pki
{

std::string convert_asn1_url(const Url_t &url, bool add_trailing_slash)
{
    std::string url_str(url.buf, url.buf + url.size);
    // Trim trailing whitespace
    boost::algorithm::trim(url_str);
    // Make sure there is a trailing slash
    if (add_trailing_slash &&!url_str.empty() && url_str.back() != '/') {
        url_str += '/';
    }
    return url_str;
}

EctlPaths::EctlPaths(const std::string &base_path)
    : ctl(base_path + "ctl/"), tlm_cert(ctl + "tlm_cert.oer"),
      ectl(ctl + "ectl.oer"), rca(base_path + "rca/"), reg(base_path + "reg/"),
      reg_key(reg + "reg_key.der"), ec(base_path + "ec/"), ec_cert(ec + "ec_cert.oer"),
      ec_key(ec + "ec_key.der"), at(base_path + "at/")
{
    // Initialize directories
    create_directories();
}

void EctlPaths::create_directories() const {
    boost::filesystem::create_directories(ctl);
    boost::filesystem::create_directories(rca);
    boost::filesystem::create_directories(reg);
    boost::filesystem::create_directories(ec);
    boost::filesystem::create_directories(at);
}

std::string EctlPaths::at_cert(uint8_t index) const
{
    std::string dir = at + std::to_string(index) + "/";
    boost::filesystem::create_directories(dir);
    return dir + "at_cert.oer";
}

std::string EctlPaths::at_key(uint8_t index) const
{
    std::string dir = at + std::to_string(index) + "/";
    boost::filesystem::create_directories(dir);
    return dir + "at_key.der";
}

std::string EctlPaths::rca_ctl(const std::string &rca_id) const
{
    std::string dir = rca + rca_id + "/";
    boost::filesystem::create_directories(dir);
    return dir + "ctl.oer";
}

std::string EctlPaths::rca_crl(const std::string &rca_id) const
{
    std::string dir = rca + rca_id + "/";
    boost::filesystem::create_directories(dir);
    return dir + "crl.oer";
}

EctlTrustStore::EctlTrustStore(const EctlPaths &paths, const Runtime &runtime,
                               CurlWrapper &curl,
                               security::Backend &backend,
                               const std::string &cpoc_url)
    : paths(paths), runtime(runtime), curl(curl), backend(backend), cpoc_url(cpoc_url)
{
    // Load TLM certificate and ECTL
    refresh_ectl();
}

std::list<security::CertificateVariant>
EctlTrustStore::lookup(const security::HashedId8 &id)
{
    refresh_ectl();
    return TrustStore::lookup(id);
}

bool EctlTrustStore::refresh_tlm_cert()
{
    bool loaded_from_cache = false;
    // If the cert is not yet loaded, try to load it from storage
    if (!tlm_cert && boost::filesystem::exists(paths.tlm_cert)) {
        tlm_cert = security::load_certificate_from_file_v3(paths.tlm_cert);

        set_next_tlm_cert_update();
        loaded_from_cache = true;

        std::cout << "Loaded TLM certificate ";
        boost::algorithm::hex(tlm_cert->calculate_hash(),
                              std::ostream_iterator<char>(std::cout));
        std::cout << std::endl;
    }

    // Check if TLM certificate is still valid
    if (runtime.now() < next_tlm_cert_update) {
        return loaded_from_cache;
    }

    // Check for updated TLM certificate
    std::string tlm_cert_url = cpoc_url + "gettlmcertificate/";
    std::cout << "Checking for updated TLM certificate from " << tlm_cert_url << std::endl;
    boost::optional<ByteBuffer> tlm_cert_buffer = curl.get_data(tlm_cert_url);
    if (!tlm_cert_buffer) {
        std::cerr << "Failed to get TLM certificate from " << tlm_cert_url << std::endl;
        // Try again in 30 seconds
        next_tlm_cert_update = runtime.now() + std::chrono::seconds(30);
        return loaded_from_cache;
    }

    // Parse TLM certificate
    security::CertificateV3 new_tlm_cert(*tlm_cert_buffer);

    // Check if TLM certificate is new
    const auto new_tlm_cert_id = new_tlm_cert.calculate_hash();
    if (tlm_cert && new_tlm_cert_id == tlm_cert->calculate_hash()) {
        std::cout << "TLM certificate is up to date" << std::endl;
        next_tlm_cert_update = runtime.now() + std::chrono::hours(24);
        return loaded_from_cache;
    }

    // Save new TLM certificate
    tlm_cert = std::move(new_tlm_cert);
    set_next_tlm_cert_update();
    security::save_certificate_to_file(paths.tlm_cert, *tlm_cert);

    std::cout << "Saved new TLM certificate ";
    boost::algorithm::hex(new_tlm_cert_id, std::ostream_iterator<char>(std::cout));
    std::cout << std::endl;

    return true;
}

void EctlTrustStore::set_next_tlm_cert_update()
{
    if (!tlm_cert) {
        return;
    }
    const security::StartAndEndValidity start_and_end = tlm_cert->get_start_and_end_validity();
    const auto validity_end = security::convert_time_point(start_and_end.end_validity);
    // 2 Months before end of validity
    next_tlm_cert_update = validity_end - std::chrono::hours(24 * 30 * 2);
    if (next_tlm_cert_update < runtime.now()) {
        // If next update is in the past, set it to 24 hours from now or validity end, whichever is earlier
        next_tlm_cert_update = std::min(runtime.now() + std::chrono::hours(24), validity_end);
    }
}

Clock::time_point EctlTrustStore::calc_next_ectl_update(const asn1::ToBeSignedTlmCtl &ectl) const
{
    const auto validity_end = security::convert_time_point(security::Time32(ectl->nextUpdate));
    // 1 Month before end of validity
    auto next_update = validity_end - std::chrono::hours(24 * 30);
    if (next_update < runtime.now()) {
        // If next update is in the past, set it to 24 hours from now or validity end, whichever is earlier
        next_update = std::min(runtime.now() + std::chrono::hours(24), validity_end);
    }
    return next_update;
}

void EctlTrustStore::refresh_ectl()
{
    if (refresh_tlm_cert()) {
        // TLM certificate was updated, so ECTL must be updated as well
        next_ectl_update = Clock::time_point();
    }
    if (!tlm_cert) {
        throw std::runtime_error("No TLM certificate available");
    }

    // Check if loaded ECTL is still valid
    if (runtime.now() < next_ectl_update) {
        return;
    }

    // Try to read ECTL from cache, if there is currently no ECTL in memory
    boost::optional<asn1::ToBeSignedTlmCtl> cached_ectl;
    boost::optional<security::Sha384Digest> cached_ectl_buffer_hash;
    if (!ectl_buffer_hash && boost::filesystem::exists(paths.ectl)) {
        std::ifstream ectl_file(paths.ectl, std::ios::in | std::ios::binary);
        ByteBuffer cached_ectl_message_bb(std::istreambuf_iterator<char>(ectl_file), {});

        cached_ectl = parse_ectl(cached_ectl_message_bb);
        if (cached_ectl) {
            cached_ectl_buffer_hash = security::calculate_sha384_digest(
                cached_ectl_message_bb.data(), cached_ectl_message_bb.size());

            std::cout << "Parsed cached ECTL ";
            boost::algorithm::hex(cached_ectl_buffer_hash->end() - 8,
                                  cached_ectl_buffer_hash->end(),
                                  std::ostream_iterator<char>(std::cout));
            std::cout << std::endl;
        } else {
            std::cerr << "Failed to parse cached ECTL" << std::endl;
        }
    }

    // Check if cached ECTL is still valid
    if (cached_ectl && runtime.now() < calc_next_ectl_update(*cached_ectl)) {
        // Load trust store from cache
        load_ectl(*cached_ectl, *cached_ectl_buffer_hash);
        std::cout << "Loaded trust store from cache" << std::endl;
        return;
    }

    // Convert TLM certificate ID to hex string
    std::string tlm_cert_id_hex;
    boost::algorithm::hex(tlm_cert->calculate_hash(), std::back_inserter(tlm_cert_id_hex));

    // Download ECTL
    std::string ectl_url = cpoc_url + "getectl/" + tlm_cert_id_hex;
    std::cout << "Checking for updated ECTL from " << ectl_url << std::endl;
    boost::optional<ByteBuffer> ectl_buffer = curl.get_data(ectl_url);
    if (!ectl_buffer) {
        std::cerr << "Failed to get ECTL from " << ectl_url << std::endl;
        recover_failed_ectl_update(cached_ectl, cached_ectl_buffer_hash);
        return;
    }

    // Check if ECTL is new
    security::Sha384Digest new_ectl_buffer_hash = security::calculate_sha384_digest(
        ectl_buffer->data(), ectl_buffer->size());
    if (new_ectl_buffer_hash == ectl_buffer_hash) {
        std::cout << "ECTL is up to date" << std::endl;
        next_ectl_update = runtime.now() + std::chrono::hours(24);
        return;
    }

    // Parse new ECTL
    boost::optional<asn1::ToBeSignedTlmCtl> new_ectl = parse_ectl(*ectl_buffer);
    if (!new_ectl) {
        std::cerr << "Failed to parse new ECTL" << std::endl;
        recover_failed_ectl_update(cached_ectl, cached_ectl_buffer_hash);
        return;
    }

    // Load new ECTL
    if (!load_ectl(*new_ectl, new_ectl_buffer_hash)) {
        std::cerr << "Failed to load new ECTL" << std::endl;
        recover_failed_ectl_update(cached_ectl, cached_ectl_buffer_hash);
        return;
    }

    // Save new ECTL
    std::ofstream ectl_file(paths.ectl, std::ios::out | std::ios::binary);
    ectl_file.write(reinterpret_cast<const char *>(ectl_buffer->data()), ectl_buffer->size());
    ectl_file.close();

    std::cout << "Saved new ECTL ";
    boost::algorithm::hex(new_ectl_buffer_hash.end() - 8,
                          new_ectl_buffer_hash.end(),
                          std::ostream_iterator<char>(std::cout));
    std::cout << std::endl;
}

void EctlTrustStore::recover_failed_ectl_update(
    const boost::optional<asn1::ToBeSignedTlmCtl> &cached_ectl,
    const boost::optional<security::Sha384Digest> &cached_ectl_buffer_hash) {
    if (cached_ectl && cached_ectl_buffer_hash) {
        // Load trust store from cache
        if (load_ectl(*cached_ectl, *cached_ectl_buffer_hash)) {
            std::cout << "Loaded trust store from expired cache" << std::endl;
            return;
        }
        throw std::runtime_error("Trust store empty and failed to load trust store from expired cache");
    }

    if (ectl_buffer_hash) {
        // Store is already populated, keep it as is
        std::cout << "Keeping ECTL trust store as is" << std::endl;
        // Try again in 30 seconds
        next_ectl_update = runtime.now() + std::chrono::seconds(30);
        return;
    }

    throw std::runtime_error("Trust store empty and no cached backup ECTL available");
}

boost::optional<asn1::ToBeSignedTlmCtl>
EctlTrustStore::parse_ectl(const ByteBuffer &ectl_buffer) const
{
    // Put tlm_cert into verification trust store
    if (!tlm_cert) {
        std::cerr << "No TLM certificate available in parse_ectl" << std::endl;
        return boost::none;
    }
    security::TrustStore tlm_trust_store;
    tlm_trust_store.insert(*tlm_cert);
    security::DefaultCertificateValidator tlm_cert_validator(backend, boost::none, tlm_trust_store);

    auto etsi_ts_102_941_data = parse_etsi_ts_102_941_data(
        ectl_buffer, tlm_cert->calculate_hash(), tlm_cert_validator);
    if (!etsi_ts_102_941_data) {
        return boost::none;
    }

    auto &content = etsi_ts_102_941_data.get()->content;
    if (content.present != EtsiTs102941DataContent_PR_certificateTrustListTlm) {
        std::cerr << "ECTL message does not contain a TLM certificate trust list" << std::endl;
        return boost::none;
    }

    asn1::ToBeSignedTlmCtl ectl;
    std::swap(*ectl, content.choice.certificateTrustListTlm);
    return ectl;
}

boost::optional<asn1::ToBeSignedRcaCtl>
EctlTrustStore::parse_rca_ctl(const ByteBuffer &buffer, const security::HashedId8 &rca_id)
{
    // RCA cert should be in trust store, so we can use it for verification
    security::DefaultCertificateValidator rca_cert_validator(backend, boost::none, *this);

    auto etsi_ts_102_941_data =
        parse_etsi_ts_102_941_data(buffer, rca_id, rca_cert_validator);
    if (!etsi_ts_102_941_data) {
        return boost::none;
    }

    auto &content = etsi_ts_102_941_data.get()->content;
    if (content.present != EtsiTs102941DataContent_PR_certificateTrustListRca) {
        std::cerr << "RCA CTL message does not contain a RCA CTL" << std::endl;
        return boost::none;
    }

    asn1::ToBeSignedRcaCtl rca_ctl;
    std::swap(*rca_ctl, content.choice.certificateTrustListRca);
    return rca_ctl;
}

bool EctlTrustStore::load_ectl(const asn1::ToBeSignedTlmCtl &ectl, const security::Sha384Digest &buffer_hash)
{
    // Clear trust store
    rca_metadata_map.clear();
    m_certificates.clear();

    // Check version and if isFullCtl is set
    if (ectl->version != Version_v1) {
        std::cerr << "ECTL has unsupported version " << ectl->version << std::endl;
        return false;
    }
    if (!ectl->isFullCtl) {
        std::cerr << "ECTL is not a full certificate trust list" << std::endl;
        return false;
    }

    const auto &ectl_commands = ectl->ctlCommands.list;
    for (int i = 0; i < ectl_commands.count; ++i) {
        const auto &ectl_command = *ectl_commands.array[i];
        if (ectl_command.present != CtlCommand_PR_add) {
            std::cerr << "ECTL command has unsupported type " << ectl_command.present << std::endl;
            next_ectl_update = runtime.now() + std::chrono::seconds(30);
            return false;
        }

        const auto &ectl_entry = ectl_command.choice.add;
        if (ectl_entry.present == CtlEntry_PR_rca) {
            // Add RCA certificate to trust store
            const auto &rca = ectl_entry.choice.rca.selfsignedRootCa;
            insert(security::CertificateV3(rca));
        } else if (ectl_entry.present == CtlEntry_PR_dc) {
            // Set DC URL for every certificate in DC entry
            const auto &dc = ectl_entry.choice.dc;
            const auto &dc_url = dc.url;
            for (int j = 0; j < dc.cert.list.count; ++j) {
                const auto cert_id = asn1::HashedId8_asn_to_HashedId8(*dc.cert.list.array[j]);
                rca_metadata_map[cert_id].dc_url = convert_asn1_url(dc_url, true);
            }
        } else if (ectl_entry.present == CtlEntry_PR_tlm) {
            // Ignore TLM certificate
        } else {
            std::cerr << "ECTL entry has unsupported type " << ectl_entry.present << std::endl;
            next_ectl_update = runtime.now() + std::chrono::seconds(30);
            return false;
        }
    }

    // Set next_ectl_update and hash
    ectl_buffer_hash = buffer_hash;
    next_ectl_update = calc_next_ectl_update(ectl);
    return true;
}

bool EctlTrustStore::is_revoked(const security::HashedId8 &rca_id,
                                const security::HashedId8 &subcert_id)
{
    // TODO: download and parse CRLs
    const auto &rca_metadata = rca_metadata_map.find(rca_id);
    if (rca_metadata == rca_metadata_map.end()) {
        return false;
    }

    const auto &revoked_subcerts = rca_metadata->second.revoked_subcerts;
    if (!revoked_subcerts) {
        return false;
    }

    return revoked_subcerts->find(subcert_id) != revoked_subcerts->end();
}

void EctlTrustStore::refresh_rca_ctl(const security::HashedId8 &rca_id, RcaMetadata &metadata)
{
    std::string rca_id_hex;
    boost::algorithm::hex(rca_id, std::back_inserter(rca_id_hex));

    // Check if update is needed
    if (metadata.next_ctl_update > runtime.now()) {
        return;
    }

    const auto &dc_url = metadata.dc_url;
    if (dc_url.empty()) {
        std::cerr << "DC URL for RCA " << rca_id_hex << " is empty" << std::endl;
        return;
    }

    // Try to load from cache if list is not initialized
    std::string rca_ctl_path = paths.rca_ctl(rca_id_hex);
    if (!metadata.subcerts && boost::filesystem::exists(rca_ctl_path)) {
        std::ifstream rca_ctl_file(rca_ctl_path, std::ios::in | std::ios::binary);
        ByteBuffer cached_rca_ctl_bb(std::istreambuf_iterator<char>(rca_ctl_file), {});
        asn1::ToBeSignedRcaCtl cached_rca_ctl;
        cached_rca_ctl.decode(cached_rca_ctl_bb);

        if (load_rca_ctl(cached_rca_ctl, metadata) && metadata.next_ctl_update > runtime.now()) {
            return;
        }
    }

    // Download RCA CTL
    std::string cert_url = dc_url + "getctl/" + rca_id_hex;
    std::cout << "Downloading RCA CTL from " << cert_url << std::endl;
    boost::optional<ByteBuffer> rca_ctl_msg_bb = curl.get_data(cert_url);
    if (!rca_ctl_msg_bb) {
        std::cerr << "Failed to get RCA CTL from " << cert_url << std::endl;
        metadata.next_ctl_update = runtime.now() + std::chrono::minutes(5);
        return;
    }

    // Parse RCA CTL
    boost::optional<asn1::ToBeSignedRcaCtl> rca_ctl = parse_rca_ctl(*rca_ctl_msg_bb, rca_id);
    if (!rca_ctl) {
        std::cerr << "Failed to parse RCA CTL" << std::endl;
        metadata.next_ctl_update = runtime.now() + std::chrono::minutes(5);
        return;
    }

    // Load RCA CTL
    if (!load_rca_ctl(*rca_ctl, metadata)) {
        std::cerr << "Failed to load RCA CTL" << std::endl;
        metadata.next_ctl_update = runtime.now() + std::chrono::minutes(5);
        return;
    }

    // Save RCA CTL to cache
    auto rca_ctl_bb = rca_ctl->encode();
    std::ofstream rca_ctl_file(rca_ctl_path, std::ios::out | std::ios::binary);
    rca_ctl_file.write(reinterpret_cast<const char *>(rca_ctl_bb.data()), rca_ctl_bb.size());
    rca_ctl_file.close();
    std::cout << "Saved RCA CTL to " << paths.rca_ctl(rca_id_hex) << std::endl;
}

bool EctlTrustStore::load_rca_ctl(const asn1::ToBeSignedRcaCtl &rca_ctl, RcaMetadata &metadata) const
{
    // Check version and if isFullCtl is set
    if (rca_ctl->version != Version_v1) {
        std::cerr << "RCA CTL has unsupported version " << rca_ctl->version << std::endl;
        return false;
    }
    if (!rca_ctl->isFullCtl) {
        std::cerr << "RCA CTL is not a full certificate trust list" << std::endl;
        return false;
    }

    // Reset old subcertificate list
    metadata.subcerts = std::map<security::HashedId8, SubCertificateV3>();
    auto &subcerts = *metadata.subcerts;

    const auto &rca_ctl_commands = rca_ctl->ctlCommands.list;
    for (int i = 0; i < rca_ctl_commands.count; ++i) {
        const auto &rca_ctl_command = *rca_ctl_commands.array[i];
        if (rca_ctl_command.present != CtlCommand_PR_add) {
            std::cerr << "RCA CTL command has unsupported type " << rca_ctl_command.present << std::endl;
            continue;
        }

        const auto &rca_ctl_entry = rca_ctl_command.choice.add;
        if (rca_ctl_entry.present == CtlEntry_PR_aa) {
            // Store AA subcertificate
            const auto &aa_entry = rca_ctl_entry.choice.aa;
            security::CertificateV3 aa_cert(aa_entry.aaCertificate);
            const auto aa_access_point_url = convert_asn1_url(aa_entry.accessPoint, false);

            const auto aa_id = aa_cert.calculate_hash();
            subcerts[aa_id] = SubCertificateV3{
                std::move(aa_cert), aa_access_point_url, SubCaType::AA};
        } else if (rca_ctl_entry.present == CtlEntry_PR_ea) {
            // Store EA subcertificate
            const auto &ea_entry = rca_ctl_entry.choice.ea;
            security::CertificateV3 ea_cert(ea_entry.eaCertificate);
            boost::optional<std::string> ea_access_point_url;
            if (ea_entry.itsAccessPoint) {
                ea_access_point_url = convert_asn1_url(*ea_entry.itsAccessPoint, false);
            }

            const auto ea_id = ea_cert.calculate_hash();
            subcerts[ea_id] = SubCertificateV3{
                std::move(ea_cert), ea_access_point_url, SubCaType::EA};
            continue;
        } else if (rca_ctl_entry.present != CtlEntry_PR_dc) {
            // Skip RCA DC entry
            std::cerr << "RCA CTL entry has unsupported type " << rca_ctl_entry.present << std::endl;
        }
    }

    // Set next update to 1 month before nextUpdate
    const auto validity_end = security::convert_time_point(security::Time32(rca_ctl->nextUpdate));
    metadata.next_ctl_update = validity_end - std::chrono::hours(24 * 30);
    if (metadata.next_ctl_update < runtime.now()) {
        // If next update is in the past, set it to 24 hours from now or validity end, whichever is earlier
        metadata.next_ctl_update = std::min(runtime.now() + std::chrono::hours(24), validity_end);
    }

    return true;
}

boost::optional<SubCertificateV3>
EctlTrustStore::get_subcert(const security::HashedId8 &rca_id,
                            const security::HashedId8 &subcert_id)
{
    std::string rca_id_hex;
    boost::algorithm::hex(rca_id, std::back_inserter(rca_id_hex));
    std::string subcert_id_hex;
    boost::algorithm::hex(subcert_id, std::back_inserter(subcert_id_hex));
    std::cout << "Looking up subcertificate " << subcert_id_hex << " from RCA " << rca_id_hex << std::endl;

    // Check if subcertificate is revoked
    if (is_revoked(rca_id, subcert_id)) {
        std::cerr << "Subcertificate " << subcert_id_hex << " is revoked" << std::endl;
        return boost::none;
    }

    const auto &rca_metadata_find = rca_metadata_map.find(rca_id);
    if (rca_metadata_find == rca_metadata_map.end()) {
        std::cerr << "RCA " << rca_id_hex << " is not in trust store" << std::endl;
        return boost::none;
    }
    RcaMetadata &rca_metadata = rca_metadata_find->second;

    // Refresh RCA CTL if needed
    refresh_rca_ctl(rca_id, rca_metadata);

    // Find subcertificate
    const auto &subcerts = rca_metadata.subcerts;
    if (!subcerts) {
        return boost::none;
    }
    const auto &subcert = subcerts->find(subcert_id);
    if (subcert == subcerts->end()) {
        std::cerr << "Subcertificate " << subcert_id_hex << " not found" << std::endl;
        return boost::none;
    }
    return subcert->second;
}

boost::optional<asn1::EtsiTs102941Data>
EctlTrustStore::parse_etsi_ts_102_941_data(const ByteBuffer &message_buffer,
                                           const security::HashedId8 &expected_signer_id,
                                           security::CertificateValidator &cert_validator) const
{
    // Validate signature
    security::SecuredMessageVariant sec_packet = security::SecuredMessageV3(message_buffer);
    security::VerifyRequest verify_request(sec_packet);
    auto verify_res =
        security::verify_v3(verify_request, runtime, boost::none, cert_validator,
                            backend, boost::none, boost::none, boost::none);
    if (verify_res.report != security::VerificationReport::Success) {
        std::cerr << "Failed to verify signature" << std::endl;
        return boost::none;
    }
    if (!verify_res.certificate_id) {
        std::cerr << "No certificate ID in parse_etsi_ts_102_941_data" << std::endl;
        return boost::none;
    }
    if (verify_res.certificate_id.get() != expected_signer_id) {
        std::cerr << "EtsiTs102941Data is not signed by expected signer" << std::endl;
        return boost::none;
    }

    // Extract EtsiTs102941Data
    const security::SecuredMessageV3 &sec_packet_v3 =
        boost::get<security::SecuredMessageV3>(sec_packet);
    asn1::EtsiTs102941Data etsi_ts102_941_data;
    etsi_ts102_941_data.decode(sec_packet_v3.get_payload());

    return etsi_ts102_941_data;
}

} // namespace pki
} // namespace vanetza
