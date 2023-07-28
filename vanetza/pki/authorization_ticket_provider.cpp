#include <vanetza/pki/authorization_ticket_provider.hpp>
#include <vanetza/pki/authorization_tickets.hpp>
#include <vanetza/security/persistence.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <fstream>

namespace vanetza
{
namespace pki
{

AuthorizationTicketProvider::AuthorizationTicketProvider(
    uint8_t num_authorization_tickets,
    security::CertificateProvider &ec_provider,
    const SubCertificateV3 &ea_certificate,
    const SubCertificateV3 &aa_certificate,
    security::BackendOpenSsl &backend,
    const Runtime &runtime,
    CurlWrapper &curl,
    const EctlPaths &ectl_paths,
    const boost::optional<asn1::SequenceOfPsidSsp> &psid_ssp_list)
    : num_authorization_tickets(num_authorization_tickets), ec_provider(ec_provider),
      ea_certificate(ea_certificate), aa_certificate(aa_certificate),
      backend(backend), runtime(runtime), curl(curl),
      ectl_paths(ectl_paths), psid_ssp_list(psid_ssp_list)
{
    // EA certificate checks
    if (ea_certificate.type != SubCaType::EA) {
        throw std::invalid_argument("AuthorizationTicketProvider: Invalid subcert type, EA certificate required");
    }
    if (!ea_certificate.access_point_url) {
        throw std::invalid_argument("AuthorizationTicketProvider: EA certificate must have access point URL");
    }

    // AA certificate checks
    if (aa_certificate.type != SubCaType::AA) {
        throw std::invalid_argument("AuthorizationTicketProvider: Invalid subcert type, AA certificate required");
    }
    if (!aa_certificate.access_point_url) {
        throw std::invalid_argument("AuthorizationTicketProvider: AA certificate must have access point URL");
    }

    // Don't refresh here, callbacks for ID change in Router are not set up yet
}

int AuthorizationTicketProvider::version()
{
    return 3;
}

const security::ecdsa256::PrivateKey& AuthorizationTicketProvider::own_private_key()
{
    refresh_authorization_ticket();
    return *authorization_ticket_key;
}

std::list<security::CertificateVariant> AuthorizationTicketProvider::own_chain()
{
    // TODO: check this
    return {aa_certificate.certificate};
}

const security::CertificateVariant& AuthorizationTicketProvider::own_certificate()
{
    refresh_authorization_ticket();
    return *authorization_ticket;
}

bool AuthorizationTicketProvider::refresh_authorization_ticket()
{
    if (runtime.now() < next_switch) {
        return false;
    }

    // Get a random new index
    uint8_t new_index = get_next_index();
    // Potentially for expired AT, used for error recovery
    boost::optional<security::CertificateVariant> stored_at;
    boost::optional<security::openssl::EvpKey> stored_at_key;

    // Try to load AT with new index, try next if unsuccessful
    for (size_t i = 0; i < num_authorization_tickets; ++i) {
        std::string new_at_path = ectl_paths.at_cert(new_index);
        std::string new_at_key_path = ectl_paths.at_key(new_index);

        // Check if AT with new index exists
        if (boost::filesystem::exists(new_at_path)) {
            // Load and switch if not close to expiry
            stored_at = security::load_certificate_from_file_v3(ectl_paths.at_cert(new_index));
            const security::CertificateV3 &stored_at_ref =
                boost::get<security::CertificateV3>(*stored_at);

            stored_at_key = security::openssl::EvpKey::read_key(ectl_paths.at_key(new_index));

            const security::StartAndEndValidity start_and_end = stored_at_ref.get_start_and_end_validity();
            const auto validity_end = security::convert_time_point(start_and_end.end_validity);
            if (validity_end > runtime.now() + std::chrono::minutes(5)) {
                set_authorization_ticket(new_index, stored_at_ref, *stored_at_key);
                return true;
            }
        }

        // Request and switch to new AT
        std::cout << "Trying to update authorization ticket " << static_cast<int>(new_index) << std::endl;
        if (authorize(new_index)) {
            return true;
        }

        std::cout << "Failed to update authorization ticket " << static_cast<int>(new_index) << std::endl;
        // Try next index, skip current index
        do {
            new_index = (new_index + 1) % num_authorization_tickets;
        } while (new_index == current_index);
    }

    if (!stored_at || !stored_at_key) {
        if (!authorization_ticket) {
            throw std::runtime_error("Failed to load any authorization ticket, aborting");
        }
        std::cerr << "Failed to load any authorization ticket, keeping current AT" << std::endl;
        return false;
    }

    std::cerr << "Loading outdated AT" << std::endl;

    authorization_ticket = stored_at;
    authorization_ticket_key = stored_at_key->private_key();
    current_index = new_index;

    // Try again in 5 minutes
    next_switch = runtime.now() + std::chrono::minutes(5);
    return true;
}

bool AuthorizationTicketProvider::authorize(uint8_t new_index)
{
    // Generate new EC verification key
    const security::CertificateV3 &ec = boost::get<security::CertificateV3>(ec_provider.own_certificate());
    std::string curve_name = ec.get_public_key_curve_name().get();
    security::openssl::EvpKey new_ec_key(curve_name);

    // Build AuthorizationRequest message
    security::EncryptConfirm authorization_request = pki::build_at_request(
        new_ec_key, ec_provider, ea_certificate.certificate,
        aa_certificate.certificate, backend, runtime, psid_ssp_list, curve_name);

    auto new_authorization_ticket = run_authorization_request(authorization_request);
    if (!new_authorization_ticket) {
        return false;
    }

    std::cout << "Authorization successful" << std::endl;
    set_authorization_ticket(new_index, *new_authorization_ticket, new_ec_key);
    save_new_authorization_ticket(new_index, *new_authorization_ticket, new_ec_key);
    return true;
}

boost::optional<security::CertificateV3> AuthorizationTicketProvider::run_authorization_request(
    const security::EncryptConfirm &authorization_request)
{
    vanetza::ByteBuffer authorization_request_bb = authorization_request.secured_message.serialize();
    const std::string &authorization_url = aa_certificate.access_point_url.get();
    std::cout << "Sending authorization request to " << authorization_url << std::endl;
    boost::optional<ByteBuffer> authorization_response =
        curl.post_its_request(authorization_url, authorization_request_bb);
    if (!authorization_response) {
        std::cerr << "Authorization request failed" << std::endl;
        return boost::none;
    }

    return decode_at_response(*authorization_response,
                              authorization_request.session_key,
                              aa_certificate.certificate, backend, runtime);
}

void AuthorizationTicketProvider::set_next_switch()
{
    if (!authorization_ticket) {
        return;
    }
    const security::CertificateV3 &certificate = boost::get<security::CertificateV3>(*authorization_ticket);
    const security::StartAndEndValidity start_and_end = certificate.get_start_and_end_validity();
    const auto validity_end = security::convert_time_point(start_and_end.end_validity);

    // TODO: Timeout conditions
    auto timeout = runtime.now() + std::chrono::minutes(5);
    next_switch = std::min(timeout, validity_end);
}

uint8_t AuthorizationTicketProvider::get_next_index() const
{
    if (num_authorization_tickets < 2) {
        return 0;
    }

    while (true) {
        uint8_t index = backend.random_bytes(1)[0] % num_authorization_tickets;
        if (index != current_index) {
            return index;
        }
    }
}

void AuthorizationTicketProvider::set_authorization_ticket(
    uint8_t index, const security::CertificateV3 &certificate,
    const security::openssl::EvpKey &private_key)
{
    std::cout << "Switching to authorization ticket " << static_cast<int>(index) << std::endl;
    authorization_ticket = certificate;
    authorization_ticket_key = private_key.private_key();
    current_index = index;
    set_next_switch();
}

void AuthorizationTicketProvider::save_new_authorization_ticket(
    uint8_t index, const security::CertificateV3 &certificate,
    const security::openssl::EvpKey &private_key) const
{
    security::save_certificate_to_file(ectl_paths.at_cert(index), certificate);
    private_key.write_private_key(ectl_paths.at_key(index));
}

} // namespace pki
} // namespace vanetza
