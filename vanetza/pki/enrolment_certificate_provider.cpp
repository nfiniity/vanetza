#include <vanetza/pki/enrolment_certificate_provider.hpp>
#include <vanetza/pki/enrolment_certificates.hpp>
#include <vanetza/security/self_certificate_provider.hpp>
#include <vanetza/security/static_certificate_provider.hpp>
#include <vanetza/security/persistence.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <fstream>

namespace vanetza
{
namespace pki
{

EnrolmentCertificateProvider::EnrolmentCertificateProvider(
    const SubCertificateV3 &ea_certificate,
    const Runtime &runtime,
    CurlWrapper &curl,
    const EctlPaths &ectl_paths,
    const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list,
    const boost::optional<std::string> &canonical_id)
    : ea_certificate(ea_certificate), runtime(runtime), curl(curl),
      ectl_paths(ectl_paths), psid_ssp_list(psid_ssp_list), canonical_id(canonical_id)
{
    // EA certificate checks
    if (ea_certificate.type != SubCaType::EA) {
        throw std::invalid_argument("EnrolmentCertificateProvider: Invalid subcert type, EA certificate required");
    }
    if (!ea_certificate.access_point_url) {
        throw std::invalid_argument("EnrolmentCertificateProvider: EA certificate must have access point URL");
    }

    refresh_enrolment_certificate();
}

int EnrolmentCertificateProvider::version()
{
    return 3;
}

const security::ecdsa256::PrivateKey& EnrolmentCertificateProvider::own_private_key()
{
    refresh_enrolment_certificate();
    return *enrolment_certificate_key;
}

std::list<security::CertificateVariant> EnrolmentCertificateProvider::own_chain()
{
    return {};
}

const security::CertificateVariant& EnrolmentCertificateProvider::own_certificate()
{
    refresh_enrolment_certificate();
    return *enrolment_certificate;
}

bool EnrolmentCertificateProvider::refresh_enrolment_certificate()
{
    // Check if certificate is loaded.
    if (!enrolment_certificate) {
        // If not, check if it can be loaded from file.
        if (boost::filesystem::exists(ectl_paths.ec_cert)) {
            std::cout << "Loading enrolment certificate from file" << std::endl;
            enrolment_certificate = security::load_certificate_from_file_v3(ectl_paths.ec_cert);

            enrolment_certificate_key =
                security::openssl::EvpKey::read_key(ectl_paths.ec_key).private_key();

            set_next_update();
        } else {
            // If not, try to enrol with registration credentials.
            std::cout << "Enrolment certificate not found, trying to enrol with registration credentials" << std::endl;

            if (!initial_enrol()) {
                throw std::runtime_error("Initial enrolment failed");
            }

            return true;
        }
    }

    if (runtime.now() < next_update) {
        return false;
    }

    std::cout << "Starting re-enrolment" << std::endl;
    return re_enrol();
}

bool EnrolmentCertificateProvider::initial_enrol()
{
    if (!canonical_id || !boost::filesystem::exists(ectl_paths.reg_key)) {
        std::cerr << "Cannot do initial enrolment without registration credentials" << std::endl;
        return false;
    }

    ByteBuffer canonical_id_bb(canonical_id->begin(), canonical_id->end());

    // Load canonical key
    security::openssl::EvpKey canonical_key =
        security::openssl::EvpKey::read_key(ectl_paths.reg_key);
    std::string curve_name = canonical_key.group_name();
    security::SelfCertificateProvider canonical_cert_provider(canonical_key.private_key(), curve_name);

    // Generate new EC verification key
    security::openssl::EvpKey new_ec_key(curve_name);

    // Build EnrolmentRequest message
    security::EncryptConfirm enrolment_request = build_enrolment_request(
        canonical_id_bb, new_ec_key, canonical_cert_provider,
        ea_certificate.certificate, runtime, psid_ssp_list, curve_name);

    auto new_enrolment_certificate = run_enrolment_request(enrolment_request);
    if (!new_enrolment_certificate) {
        return false;
    }

    std::cout << "Initial enrolment successful" << std::endl;
    set_new_enrolment_certificate(*new_enrolment_certificate, new_ec_key);
    return true;
}

bool EnrolmentCertificateProvider::re_enrol()
{
    if (!enrolment_certificate || !enrolment_certificate_key) {
        std::cerr << "Cannot do re-enrolment without loaded active EC" << std::endl;
        return false;
    }

    const security::CertificateV3 &ec = boost::get<security::CertificateV3>(*enrolment_certificate);
    security::HashedId8 ec_id = ec.calculate_hash();
    ByteBuffer ec_id_bb(ec_id.begin(), ec_id.end());

    // Load canonical key
    security::openssl::EvpKey ec_key =
        security::openssl::EvpKey::read_key(ectl_paths.ec_key);
    std::string curve_name = ec_key.group_name();
    security::StaticCertificateProvider ec_provider(*enrolment_certificate, ec_key.private_key());

    // Generate new EC verification key
    security::openssl::EvpKey new_ec_key(curve_name);

    // Build EnrolmentRequest message
    security::EncryptConfirm enrolment_request = build_enrolment_request(
        ec_id_bb, new_ec_key, ec_provider, ea_certificate.certificate, runtime,
        psid_ssp_list, curve_name);

    auto new_enrolment_certificate = run_enrolment_request(enrolment_request);
    if (!new_enrolment_certificate) {
        return false;
    }

    std::cout << "Re-enrolment successful" << std::endl;
    set_new_enrolment_certificate(*new_enrolment_certificate, new_ec_key);
    return true;
}

boost::optional<security::CertificateV3> EnrolmentCertificateProvider::run_enrolment_request(
    const security::EncryptConfirm &enrolment_request)
{
    vanetza::ByteBuffer enrolment_request_bb = enrolment_request.secured_message.serialize();
    const std::string &enrolment_url = ea_certificate.access_point_url.get();
    std::cout << "Sending enrolment request to " << enrolment_url << std::endl;
    boost::optional<ByteBuffer> enrolment_response = curl.post_its_request(enrolment_url, enrolment_request_bb);
    if (!enrolment_response) {
        std::cerr << "Enrolment request failed" << std::endl;
        next_update = runtime.now() + std::chrono::minutes(5);
        return boost::none;
    }

    // TODO: remove
    // Backup enrolment response
    std::ofstream enrolment_response_file(
        "/home/dankeroni/ectl_trust_store/enrolment_bak/ec_response.oer",
        std::ios::out | std::ios::binary);
    enrolment_response_file.write(
        reinterpret_cast<const char *>(enrolment_response->data()),
        enrolment_response->size());
    enrolment_response_file.close();

    // TODO: remove
    // Save session key
    std::ofstream session_key_file(
        "/home/dankeroni/ectl_trust_store/enrolment_bak/session_key.bin",
        std::ios::out | std::ios::binary);
    session_key_file.write(
        reinterpret_cast<const char *>(enrolment_request.session_key.data()),
        enrolment_request.session_key.size());
    session_key_file.close();

    return decode_ec_response(*enrolment_response,
                              enrolment_request.session_key,
                              ea_certificate.certificate, runtime);
}

void EnrolmentCertificateProvider::set_next_update()
{
    if (!enrolment_certificate) {
        return;
    }
    const security::CertificateV3 &certificate = boost::get<security::CertificateV3>(*enrolment_certificate);
    const security::StartAndEndValidity start_and_end = certificate.get_start_and_end_validity();
    const auto validity_end = security::convert_time_point(start_and_end.end_validity);
    // 3 Months before end of validity
    next_update = validity_end - std::chrono::hours(24 * 30 * 3);
}

void EnrolmentCertificateProvider::set_new_enrolment_certificate(
    const security::CertificateV3 &certificate,
    const security::openssl::EvpKey &private_key)
{
    enrolment_certificate = certificate;
    enrolment_certificate_key = private_key.private_key();
    set_next_update();

    // Save enrolment certificate
    security::save_certificate_to_file(ectl_paths.ec_cert, certificate);
    // Save enrolment certificate private key
    private_key.write_private_key(ectl_paths.ec_key);
}

} // namespace pki
} // namespace vanetza
