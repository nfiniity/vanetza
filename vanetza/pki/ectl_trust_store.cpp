#include <vanetza/pki/ectl_trust_store.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/verify_service.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/asn1/etsi_ts_102_941_data.hpp>
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
      ectl(ctl + "ectl.oer"), crl(base_path + "crl/"), reg(base_path + "reg/"),
      reg_key(reg + "reg_key.der"), ec(base_path + "ec/"), ec_cert(ec + "ec_cert.oer"),
      ec_key(ec + "ec_key.der"), at(base_path + "at/")
{
    // Initialize directories
    create_directories();
}

void EctlPaths::create_directories() const {
    boost::filesystem::create_directories(ctl);
    boost::filesystem::create_directories(crl);
    boost::filesystem::create_directories(reg);
    boost::filesystem::create_directories(ec);
    boost::filesystem::create_directories(at);
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
}

Clock::time_point EctlTrustStore::calc_next_ectl_update(const asn1::ToBeSignedTlmCtl &ectl) const
{
    const auto validity_end = security::convert_time_point(ectl->nextUpdate);
    // 1 Month before end of validity
    return validity_end - std::chrono::hours(24 * 30);
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

    // Validate ECTL signature
    security::SecuredMessageVariant sec_packet = security::SecuredMessageV3(ectl_buffer);
    security::VerifyRequest verify_request(sec_packet);
    auto verify_res =
        security::verify_v3(verify_request, runtime, boost::none, tlm_cert_validator,
                            backend, boost::none, boost::none, boost::none);
    if (verify_res.report != security::VerificationReport::Success) {
        std::cerr << "Failed to verify ECTL" << std::endl;
        return boost::none;
    }
    if (!verify_res.certificate_id) {
        std::cerr << "No certificate ID in parse_ectl" << std::endl;
        return boost::none;
    }
    if (verify_res.certificate_id.get() != tlm_cert->calculate_hash()) {
        std::cerr << "ECTL was not signed by TLM certificate" << std::endl;
        return boost::none;
    }

    // Extract ECTL
    const security::SecuredMessageV3 &sec_packet_v3 =
        boost::get<security::SecuredMessageV3>(sec_packet);
    asn1::EtsiTs102941Data etsi_ts102_941_data;
    etsi_ts102_941_data.decode(sec_packet_v3.get_payload());
    if (etsi_ts102_941_data->content.present != EtsiTs102941DataContent_PR_certificateTrustListTlm) {
        std::cerr << "ECTL message does not contain a TLM certificate trust list" << std::endl;
        return boost::none;
    }

    asn1::ToBeSignedTlmCtl ectl;
    std::swap(*ectl, etsi_ts102_941_data->content.choice.certificateTrustListTlm);
    return ectl;
}

boost::optional<asn1::ToBeSignedRcaCtl>
EctlTrustStore::parse_rca_ctl(const ByteBuffer &buffer, const security::HashedId8 &rca_id)
{
    // Validate CA CTL signature
    security::SecuredMessageVariant sec_packet = security::SecuredMessageV3(buffer);
    security::VerifyRequest verify_request(sec_packet);
    // CA cert should be in trust store, so we can use it for verification
    security::DefaultCertificateValidator rca_cert_validator(backend, boost::none, *this);

    auto verify_res =
        security::verify_v3(verify_request, runtime, boost::none, rca_cert_validator,
                            backend, boost::none, boost::none, boost::none);
    if (verify_res.report != security::VerificationReport::Success) {
        std::cerr << "Failed to verify RCA CTL" << std::endl;
        return boost::none;
    }
    if (!verify_res.certificate_id) {
        std::cerr << "No certificate ID in get_subcert" << std::endl;
        return boost::none;
    }
    if (verify_res.certificate_id.get() != rca_id) {
        std::cerr << "RCA CTL was not signed by given RCA ID" << std::endl;
        return boost::none;
    }

    // Extract CA CTL
    const security::SecuredMessageV3 &sec_packet_v3 =
        boost::get<security::SecuredMessageV3>(sec_packet);
    asn1::EtsiTs102941Data etsi_ts102_941_data;
    etsi_ts102_941_data.decode(sec_packet_v3.get_payload());
    if (etsi_ts102_941_data->content.present != EtsiTs102941DataContent_PR_certificateTrustListRca) {
        std::cerr << "RCA CTL message does not contain a RCA CTL" << std::endl;
        return boost::none;
    }

    asn1::ToBeSignedRcaCtl rca_ctl;
    std::swap(*rca_ctl, etsi_ts102_941_data->content.choice.certificateTrustListRca);
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
                                const security::HashedId8 &cert_id) const
{
    // TODO: download and parse CRLs
    const auto &rca_metadata = rca_metadata_map.find(rca_id);
    if (rca_metadata == rca_metadata_map.end()) {
        return false;
    }

    return rca_metadata->second.revoked_ids.find(cert_id) !=
           rca_metadata->second.revoked_ids.end();
}

boost::optional<SubCertificateV3>
EctlTrustStore::get_subcert(const security::HashedId8 &rca_id,
                            const security::HashedId8 &cert_id)
{
    std::string rca_id_hex;
    boost::algorithm::hex(rca_id, std::back_inserter(rca_id_hex));
    std::string cert_id_hex;
    boost::algorithm::hex(cert_id, std::back_inserter(cert_id_hex));
    std::cout << "Requesting subcertificate " << cert_id_hex << " from RCA " << rca_id_hex << std::endl;

    const auto &rca_metadata = rca_metadata_map.find(rca_id);
    if (rca_metadata == rca_metadata_map.end()) {
        std::cerr << "No metadata for RCA " << rca_id_hex << std::endl;
        return boost::none;
    }

    const auto &dc_url = rca_metadata->second.dc_url;
    if (dc_url.empty()) {
        std::cerr << "DC URL for RCA " << rca_id_hex << " is empty" << std::endl;
        return boost::none;
    }

    // Download CA CTL
    std::string cert_url = dc_url + "getctl/" + rca_id_hex;
    std::cout << "Downloading RCA CTL from " << cert_url << std::endl;
    boost::optional<ByteBuffer> rca_ctl_buffer = curl.get_data(cert_url);
    if (!rca_ctl_buffer) {
        std::cerr << "Failed to get RCA CTL from " << cert_url << std::endl;
        return boost::none;
    }

    // Parse CA CTL
    boost::optional<asn1::ToBeSignedRcaCtl> rca_ctl = parse_rca_ctl(*rca_ctl_buffer, rca_id);
    if (!rca_ctl) {
        std::cerr << "Failed to parse RCA CTL" << std::endl;
        return boost::none;
    }

    // TODO: cache CA CTLs

    return find_subcert(*rca_ctl, cert_id);
}

boost::optional<SubCertificateV3>
EctlTrustStore::find_subcert(const asn1::ToBeSignedRcaCtl &rca_ctl,
                             const security::HashedId8 &cert_id) const
{
    // Check version and if isFullCtl is set
    if (rca_ctl->version != Version_v1) {
        std::cerr << "RCA CTL has unsupported version " << rca_ctl->version << std::endl;
        return boost::none;
    }
    if (!rca_ctl->isFullCtl) {
        std::cerr << "RCA CTL is not a full certificate trust list" << std::endl;
        return boost::none;
    }

    boost::optional<SubCertificateV3> subcert;
    const auto &rca_ctl_commands = rca_ctl->ctlCommands.list;
    for (int i = 0; i < rca_ctl_commands.count; ++i) {
        const auto &rca_ctl_command = *rca_ctl_commands.array[i];
        if (rca_ctl_command.present != CtlCommand_PR_add) {
            std::cerr << "RCA CTL command has unsupported type " << rca_ctl_command.present << std::endl;
            continue;
        }

        const auto &rca_ctl_entry = rca_ctl_command.choice.add;
        if (rca_ctl_entry.present == CtlEntry_PR_aa) {
            const auto &aa_entry = rca_ctl_entry.choice.aa;
            security::CertificateV3 aa_cert(aa_entry.aaCertificate);
            // Check if certificate ID matches
            if (aa_cert.calculate_hash() != cert_id) {
                continue;
            }
            std::cout << "Found AA subcertificate" << std::endl;

            const auto aa_access_point_url = convert_asn1_url(aa_entry.accessPoint, false);
            return SubCertificateV3{std::move(aa_cert), aa_access_point_url, SubCaType::AA};
        }

        if (rca_ctl_entry.present == CtlEntry_PR_ea) {
            const auto &ea_entry = rca_ctl_entry.choice.ea;
            security::CertificateV3 ea_cert(ea_entry.eaCertificate);
            // Check if certificate ID matches
            if (ea_cert.calculate_hash() != cert_id) {
                continue;
            }
            std::cout << "Found EA subcertificate" << std::endl;

            boost::optional<std::string> ea_access_point_url;
            if (ea_entry.itsAccessPoint) {
                ea_access_point_url = convert_asn1_url(*ea_entry.itsAccessPoint, false);
            }
            return SubCertificateV3{std::move(ea_cert), ea_access_point_url, SubCaType::EA};
        }

        if (rca_ctl_entry.present == CtlEntry_PR_dc) {
            // Skip RCA DC entry
            continue;
        }

        std::cerr << "RCA CTL entry has unsupported type " << rca_ctl_entry.present << std::endl;
        continue;
    }

    std::cerr << "No matching subcertificate found in RCA CTL" << std::endl;
    return boost::none;
}

} // namespace pki
} // namespace vanetza
