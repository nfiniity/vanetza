#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/common/serialization_buffer.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/length_coding.hpp>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/signer_info.hpp>
#include <vanetza/security/exception.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/get.hpp>
#include <boost/variant/static_visitor.hpp>
#include <vanetza/asn1/etsi_certificate.hpp>
#include <vanetza/asn1/ieee1609dot2_certificate.hpp>
#include <vanetza/asn1/utils.hpp>
#include <vanetza/geonet/units.hpp>
#include <memory>
#include <algorithm>
#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{

size_t get_size(const Certificate& cert)
{
    size_t size = sizeof(cert.version());
    size += get_size(cert.signer_info);
    size += get_size(cert.subject_info);
    size += get_size(cert.subject_attributes);
    size += length_coding_size(get_size(cert.subject_attributes));
    size += get_size(cert.validity_restriction);
    size += length_coding_size(get_size(cert.validity_restriction));
    size += get_size(cert.signature);
    return size;
}


void serialize(OutputArchive& ar, const Certificate& cert)
{
    serialize(ar, host_cast(cert.version()));
    serialize(ar, cert.signer_info);
    serialize(ar, cert.subject_info);
    serialize(ar, cert.subject_attributes);
    serialize(ar, cert.validity_restriction);
    serialize(ar, cert.signature);
}

size_t deserialize(InputArchive& ar, Certificate& cert)
{
    uint8_t version = 0;
    deserialize(ar, version);
    size_t size = sizeof(cert.version());
    if (2 == version) {
        size += deserialize(ar, cert.signer_info);
        size += deserialize(ar, cert.subject_info);
        size += deserialize(ar, cert.subject_attributes);
        size += length_coding_size(get_size(cert.subject_attributes));
        size += deserialize(ar, cert.validity_restriction);
        size += length_coding_size(get_size(cert.validity_restriction));
        size += deserialize(ar, cert.signature);
    } else {
        throw deserialization_error("Unsupported Certificate version");
    }

    return size;
}

ByteBuffer convert_for_signing(const Certificate& cert)
{
    ByteBuffer buf;
    byte_buffer_sink sink(buf);

    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream);

    const uint8_t version = cert.version();
    ar << version;
    serialize(ar, cert.signer_info);
    serialize(ar, cert.subject_info);
    serialize(ar, cert.subject_attributes);
    serialize(ar, cert.validity_restriction);

    stream.close();
    return buf;
}

void sort(Certificate& cert)
{
    cert.subject_attributes.sort([](const SubjectAttribute& a, const SubjectAttribute& b) {
        const SubjectAttributeType type_a = get_type(a);
        const SubjectAttributeType type_b = get_type(b);

        // all fields must be encoded in ascending order
        using enum_int = std::underlying_type<SubjectAttributeType>::type;
        return static_cast<enum_int>(type_a) < static_cast<enum_int>(type_b);
    });

    cert.validity_restriction.sort([](const ValidityRestriction& a, const ValidityRestriction& b) {
        const ValidityRestrictionType type_a = get_type(a);
        const ValidityRestrictionType type_b = get_type(b);

        // all fields must be encoded in ascending order
        using enum_int = std::underlying_type<ValidityRestrictionType>::type;
        return static_cast<enum_int>(type_a) < static_cast<enum_int>(type_b);
    });
}

boost::optional<Uncompressed> get_uncompressed_public_key(const Certificate& cert, Backend& backend)
{
    boost::optional<Uncompressed> public_key_coordinates;
    for (auto& attribute : cert.subject_attributes) {
        if (get_type(attribute) == SubjectAttributeType::Verification_Key) {
            const VerificationKey& verification_key = boost::get<VerificationKey>(attribute);
            const EccPoint& ecc_point = boost::get<ecdsa_nistp256_with_sha256>(verification_key.key).public_key;
            public_key_coordinates = backend.decompress_point(ecc_point);
            break;
        }
    }

    return public_key_coordinates;
}

boost::optional<ecdsa256::PublicKey> get_public_key(const Certificate& cert, Backend& backend)
{
    auto unc = get_uncompressed_public_key(cert, backend);
    boost::optional<ecdsa256::PublicKey> result;
    ecdsa256::PublicKey pub;
    if (unc && unc->x.size() == pub.x.size() && unc->y.size() == pub.y.size()) {
        std::copy_n(unc->x.begin(), pub.x.size(), pub.x.data());
        std::copy_n(unc->y.begin(), pub.y.size(), pub.y.data());
        result = std::move(pub);
    }
    return result;
}

HashedId8 calculate_hash(const Certificate& cert)
{
    Certificate canonical_cert = cert;

    // canonical encoding according to TS 103 097 V1.2.1, section 4.2.12
    boost::optional<EcdsaSignature> signature = extract_ecdsa_signature(cert.signature);
    if (signature) {
        struct canonical_visitor : public boost::static_visitor<EccPoint>
        {
            EccPoint operator()(const X_Coordinate_Only& x_only) const
            {
                return x_only;
            }

            EccPoint operator()(const Compressed_Lsb_Y_0& y0) const
            {
                return X_Coordinate_Only { y0.x };
            }

            EccPoint operator()(const Compressed_Lsb_Y_1& y1) const
            {
                return X_Coordinate_Only { y1.x };
            }

            EccPoint operator()(const Uncompressed& unc) const
            {
                return X_Coordinate_Only { unc.x };
            }
        };

        EcdsaSignature canonical_sig;
        canonical_sig.s = signature->s;
        canonical_sig.R = boost::apply_visitor(canonical_visitor(), signature->R);
        assert(get_type(canonical_sig.R) == EccPointType::X_Coordinate_Only);
        canonical_cert.signature = canonical_sig;
    }

    ByteBuffer bytes;
    serialize_into_buffer(canonical_cert, bytes);

    HashedId8 id;
    Sha256Digest digest = calculate_sha256_digest(bytes.data(), bytes.size());
    assert(digest.size() >= id.size());
    std::copy(digest.end() - id.size(), digest.end(), id.begin());
    return id;
}

const SubjectAttribute* Certificate::get_attribute(SubjectAttributeType sat) const
{
    const SubjectAttribute* match = nullptr;
    for (auto& attribute : subject_attributes) {
        if (get_type(attribute) == sat) {
            match = &attribute;
            break;
        }
    }
    return match;
}

const ValidityRestriction* Certificate::get_restriction(ValidityRestrictionType vrt) const
{
    const ValidityRestriction* match = nullptr;
    for (auto& restriction : validity_restriction) {
        if (get_type(restriction) == vrt) {
            match = &restriction;
            break;
        }
    }
    return match;
}

void Certificate::remove_attribute(SubjectAttributeType type)
{
    for (auto it = subject_attributes.begin(); it != subject_attributes.end(); /* noop */) {
        if (get_type(*it) == type) {
            it = subject_attributes.erase(it);
        } else {
            ++it;
        }
    }
}

void Certificate::remove_restriction(ValidityRestrictionType type)
{
    for (auto it = validity_restriction.begin(); it != validity_restriction.end(); /* noop */) {
        if (get_type(*it) == type) {
            it = validity_restriction.erase(it);
        } else {
            ++it;
        }
    }
}

void Certificate::add_permission(ItsAid aid)
{
    for (auto& item : subject_attributes) {
        if (get_type(item) == SubjectAttributeType::ITS_AID_List) {
            auto& aid_list = boost::get<std::list<IntX>>(item);
            aid_list.push_back(IntX(aid));
            return;
        }
    }

    subject_attributes.push_back(std::list<IntX>({ IntX(aid) }));
}

void Certificate::add_permission(ItsAid aid, const ByteBuffer& ssp)
{
    ItsAidSsp permission({ IntX(aid), ssp });

    for (auto& item : subject_attributes) {
        if (get_type(item) == SubjectAttributeType::ITS_AID_SSP_List) {
            auto& aid_ssp_list = boost::get<std::list<ItsAidSsp> >(item);
            aid_ssp_list.push_back(permission);
            return;
        }
    }

    subject_attributes.push_back(std::list<ItsAidSsp>({ permission }));
}

/* CertificateV3*/

CertificateV3::CertificateV3(){
    vanetza::ByteBuffer white_cert_buffer{
        0x80, 0x03, 0x00, 0x81, 0x00, 0x19, 0x81, 0x0f, 0x72, 0x6f, 0x6f, 0x74, 0x63, 0x61, 0x2e, 0x74,
 0x65, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x10, 0x5b, 0x18,
 0x86, 0x00, 0x23, 0x01, 0x01, 0x80, 0x01, 0x00, 0x80, 0x01, 0x00, 0x01, 0x01, 0x60, 0x81, 0x01,
 0x01, 0x00, 0x00, 0x80, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    this->certificate.decode(white_cert_buffer);
}

CertificateV3::~CertificateV3(){
}

CertificateV3::CertificateV3(vanetza::ByteBuffer certificate){
    this->certificate.decode(certificate);
}

CertificateV3::CertificateV3(const CertificateV3& certificate){
    vanetza::ByteBuffer buffer = certificate.serialize();
    this->certificate.decode(buffer);
}

CertificateV3::CertificateV3(const Certificate_t& certificate){
    if(certificate.type == CertificateType_explicit){
        vanetza::asn1::Ieee1609Dot2Certificate temp;
        *temp = certificate;
        vanetza::ByteBuffer buffer = temp.encode();
        this->certificate.decode(buffer);
    }
}

void CertificateV3::copy_into(Certificate_t* cert) const{
    vanetza::ByteBuffer cert_buffer = this->certificate.encode();
    vanetza::asn1::decode_oer(asn_DEF_Certificate, (void**)(&cert), cert_buffer);
}

vanetza::ByteBuffer CertificateV3::serialize() const {
    return this->certificate.encode();
}

vanetza::security::StartAndEndValidity CertificateV3::get_start_and_end_validity() const {
    vanetza::security::StartAndEndValidity start_and_end;
    start_and_end.start_validity = Time32(this->certificate->toBeSigned.validityPeriod.start);
    Time32 duration = 0;
    switch (this->certificate->toBeSigned.validityPeriod.duration.present)
    {
    case Duration_PR_NOTHING:
        break;
    case Duration_PR_microseconds:
        duration += (int)this->certificate->toBeSigned.validityPeriod.duration.choice.microseconds/1000000;
        break;
    case Duration_PR_milliseconds:
        duration += (int)this->certificate->toBeSigned.validityPeriod.duration.choice.milliseconds/1000;
        break;
    case Duration_PR_seconds:
        duration += (int)this->certificate->toBeSigned.validityPeriod.duration.choice.seconds;
        break;
    case Duration_PR_minutes:
        duration += (int)this->certificate->toBeSigned.validityPeriod.duration.choice.minutes*60;
        break;
    case Duration_PR_hours:
        duration += (int)this->certificate->toBeSigned.validityPeriod.duration.choice.hours*60*60;
        break;
    case Duration_PR_sixtyHours:
        duration += (int)this->certificate->toBeSigned.validityPeriod.duration.choice.sixtyHours*60*60*60;
        break;
    case Duration_PR_years:
        duration += (int)this->certificate->toBeSigned.validityPeriod.duration.choice.years*60*60*24*365;
        break;
    default:
        break;
    }
    start_and_end.end_validity = start_and_end.start_validity + duration;
    return start_and_end;
}

Clock::duration CertificateV3::get_validity_duration() const {
    vanetza::security::StartAndEndValidity start_and_end = this->get_start_and_end_validity();
    vanetza::Clock::duration time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time()).time_since_epoch();
    vanetza::Clock::duration end_time = std::chrono::seconds(start_and_end.end_validity);
    return end_time-time_now;
}

std::shared_ptr<GeographicRegion> CertificateV3::get_geographic_region() const
{
    std::shared_ptr<GeographicRegion> to_return;
    if (this->certificate->toBeSigned.region){
        to_return.reset(new GeographicRegion(vanetza::asn1::GeographicRegionAsn_to_GeographicRegion(
        *this->certificate->toBeSigned.region
    )));
    }
    return to_return;
}

std::list<PsidSsp_t> CertificateV3::get_app_permissions() const{
    std::list<PsidSsp_t> to_return{};
    int number_of_psid = this->certificate->toBeSigned.appPermissions->list.count;
    if (number_of_psid > 0){
        for (int i=0;i<number_of_psid; i++){
            to_return.push_back(*this->certificate->toBeSigned.appPermissions->list.array[i]);
        }
    }
    return to_return;
}

void CertificateV3::EccP256CurvePoint_to_x_only(EccP256CurvePoint_t& curve_point) const{
    switch(curve_point.present){
	    case EccP256CurvePoint_PR_compressed_y_0:
            curve_point.choice.x_only = curve_point.choice.compressed_y_0;
            break;
	    case EccP256CurvePoint_PR_compressed_y_1:
            curve_point.choice.x_only = curve_point.choice.compressed_y_1;
            break;
	    case EccP256CurvePoint_PR_uncompressedP256:
            curve_point.choice.x_only = curve_point.choice.uncompressedP256.x;
            break;
    }
    curve_point.present = EccP256CurvePoint_PR_x_only;
}

ByteBuffer CertificateV3::convert_for_signing() const {
    // The hash is calculated over the ToBeSignedCertificate
    std::unique_ptr<ToBeSignedCertificate_t> to_be_signed{static_cast<ToBeSignedCertificate_t*>(vanetza::asn1::copy(asn_DEF_ToBeSignedCertificate, &(this->certificate->toBeSigned)))};

    // The standard states that all the curve points must be compressed to x-only to be hashed
    if(to_be_signed.get()->encryptionKey){
        switch (to_be_signed.get()->encryptionKey->publicKey.present){
            case BasePublicEncryptionKey_PR_eciesNistP256:
                this->EccP256CurvePoint_to_x_only(to_be_signed.get()->encryptionKey->publicKey.choice.eciesNistP256);
                break;
            case BasePublicEncryptionKey_PR_eciesBrainpoolP256r1:
                this->EccP256CurvePoint_to_x_only(to_be_signed.get()->encryptionKey->publicKey.choice.eciesBrainpoolP256r1);
                break;
        }
    }
    // Implementing the V1.3.1 which only has explicit certificates
    if(to_be_signed.get()->verifyKeyIndicator.present == VerificationKeyIndicator_PR_verificationKey){
        switch(to_be_signed.get()->verifyKeyIndicator.choice.verificationKey.present){
            case PublicVerificationKey_PR_ecdsaNistP256:
                this->EccP256CurvePoint_to_x_only(to_be_signed.get()->verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256);
                break;
	        case PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
                this->EccP256CurvePoint_to_x_only(to_be_signed.get()->verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP256r1);
                break;
	        case PublicVerificationKey_PR_ecdsaBrainpoolP384r1:
                // TODO;
                break;
        }
    }

    ByteBuffer bytes;
    bytes = vanetza::asn1::encode_oer(asn_DEF_ToBeSignedCertificate, to_be_signed.get());
    vanetza::asn1::free(asn_DEF_ToBeSignedCertificate, to_be_signed.release());
    return bytes;
}

HashedId8 CertificateV3::calculate_hash() const {
    vanetza::ByteBuffer bytes = this->convert_for_signing();
    HashedId8 id;
    Sha256Digest digest = calculate_sha256_digest(bytes.data(), bytes.size());
    assert(digest.size() >= id.size());
    std::copy(digest.end() - id.size(), digest.end(), id.begin());
    return id;
}

HashedId8 CertificateV3::get_issuer_identifier() const{
    HashedId8 to_return = {0,0,0,0,0,0,0,0};
    switch (this->certificate->issuer.present)
    {
    case IssuerIdentifier_PR_NOTHING:

        break;
	case IssuerIdentifier_PR_sha256AndDigest:
        to_return = vanetza::asn1::HashedId8_asn_to_HashedId8(this->certificate->issuer.choice.sha256AndDigest);
        break;
	case IssuerIdentifier_PR_self:
        break;
	case IssuerIdentifier_PR_sha384AndDigest:
        break;
    default:
        break;
    }
    return to_return;
}

Signature CertificateV3::get_signature() const {
    EcdsaSignature to_return;
    std::unique_ptr<EccP256CurvePoint_t> eccP256;
    switch (this->certificate->signature->present)
    {
    case Signature_PR_NOTHING:
        break;
	case Signature_PR_ecdsaNistP256Signature:
        to_return.s = vanetza::asn1::OCTET_STRING_to_ByteBuffer(
            this->certificate->signature->choice.ecdsaNistP256Signature.sSig
        );
        *eccP256 = this->certificate->signature->choice.ecdsaNistP256Signature.rSig;
        break;
	case Signature_PR_ecdsaBrainpoolP256r1Signature:
        to_return.s = vanetza::asn1::OCTET_STRING_to_ByteBuffer(
            this->certificate->signature->choice.ecdsaBrainpoolP256r1Signature.sSig
        );
        *eccP256 = this->certificate->signature->choice.ecdsaBrainpoolP256r1Signature.rSig;
        break;
	case Signature_PR_ecdsaBrainpoolP384r1Signature:
        // TODO
        break;
    default:
        break;
    }
    if (eccP256){
        switch (eccP256->present)
        {
        case EccP256CurvePoint_PR_NOTHING:
            break;
    	case EccP256CurvePoint_PR_x_only:
            to_return.R = X_Coordinate_Only{
                .x=vanetza::asn1::OCTET_STRING_to_ByteBuffer(
                    eccP256->choice.x_only
                )
                };
            break;
    	case EccP256CurvePoint_PR_fill:
            // Not covered case
            break;
    	case EccP256CurvePoint_PR_compressed_y_0:
            to_return.R = Compressed_Lsb_Y_0{
                .x=vanetza::asn1::OCTET_STRING_to_ByteBuffer(
                    eccP256->choice.compressed_y_0
                )
            };
            break;
    	case EccP256CurvePoint_PR_compressed_y_1:
            to_return.R = Compressed_Lsb_Y_1{
                .x=vanetza::asn1::OCTET_STRING_to_ByteBuffer(
                    eccP256->choice.compressed_y_1
                )
            };
            break;
    	case EccP256CurvePoint_PR_uncompressedP256:
            to_return.R = Uncompressed{
                .x=vanetza::asn1::OCTET_STRING_to_ByteBuffer(
                    eccP256->choice.uncompressedP256.x
                ),
                .y=vanetza::asn1::OCTET_STRING_to_ByteBuffer(
                    eccP256->choice.uncompressedP256.y
                )
            };
            break;
        default:
            break;
        }
    }
    return to_return;
}

std::shared_ptr<SubjectAssurance> CertificateV3::get_subject_assurance() const{
    std::shared_ptr<SubjectAssurance> to_return;
    if(this->certificate->toBeSigned.assuranceLevel){
        // Assurance Level is an Octet string with always size 1
        to_return.reset(new SubjectAssurance(this->certificate->toBeSigned.assuranceLevel->buf[0]));
    }
    return to_return;

}

boost::optional<Uncompressed> CertificateV3::get_uncompressed_public_key(Backend& backend) const
{
    boost::optional<Uncompressed> public_key_coordinates;
    EccPoint ecc_point;
    std::string curve_name;
    if (this->certificate->toBeSigned.verifyKeyIndicator.present == VerificationKeyIndicator_PR_verificationKey){
        switch (this->certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.present){
            case PublicVerificationKey_PR_ecdsaNistP256:
                curve_name = "prime256v1";
                ecc_point = vanetza::asn1::EccP256CurvePoint_to_EccPoint(this->certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256);
                break;
	        case PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
                curve_name = "brainpoolP256r1";
                ecc_point = vanetza::asn1::EccP256CurvePoint_to_EccPoint(this->certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP256r1);
                break;
            default:
                return public_key_coordinates;
        }
        public_key_coordinates = backend.decompress_point(ecc_point, curve_name);
    }

    return public_key_coordinates;
}

boost::optional<std::string> CertificateV3::get_public_key_curve_name() const
{
    boost::optional<std::string> curve_name;
    if (this->certificate->toBeSigned.verifyKeyIndicator.present == VerificationKeyIndicator_PR_verificationKey){
        switch (this->certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.present){
            case PublicVerificationKey_PR_ecdsaNistP256:
                curve_name = "prime256v1";
                break;
	        case PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
                curve_name = "brainpoolP256r1";
                break;
        }
    }
    return curve_name;
}

boost::optional<ecdsa256::PublicKey>  CertificateV3::get_public_key(Backend& backend) const
{
    auto unc = this->get_uncompressed_public_key(backend);
    if (unc) {
        return public_key_from_uncompressed(*unc);
    } else {
        return boost::none;
    }
}

boost::optional<std::string> CertificateV3::get_encryption_public_key_curve_name() const
{
    const PublicEncryptionKey_t *encryption_key = this->certificate->toBeSigned.encryptionKey;
    if (encryption_key == nullptr) return boost::none;

    const BasePublicEncryptionKey_t &public_key = encryption_key->publicKey;
    switch (public_key.present){
        case BasePublicEncryptionKey_PR_eciesNistP256:
            return std::string("prime256v1");
        case BasePublicEncryptionKey_PR_eciesBrainpoolP256r1:
            return std::string("brainpoolP256r1");
        default:
            return boost::none;
    }
}

boost::optional<Uncompressed> CertificateV3::get_encryption_uncompressed_public_key(Backend& backend) const
{
    const PublicEncryptionKey_t *encryption_key = this->certificate->toBeSigned.encryptionKey;
    if (encryption_key == nullptr) return boost::none;

    const BasePublicEncryptionKey_t &public_key = encryption_key->publicKey;
    std::string curve_name;
    const EccP256CurvePoint_t *eccP256;
    switch (public_key.present){
        case BasePublicEncryptionKey_PR_eciesNistP256:
            eccP256 = &public_key.choice.eciesNistP256;
            curve_name = "prime256v1";
            break;
        case BasePublicEncryptionKey_PR_eciesBrainpoolP256r1:
            eccP256 = &public_key.choice.eciesBrainpoolP256r1;
            curve_name = "brainpoolP256r1";
            break;
        default:
            return boost::none;
    }

    EccPoint ecc_point = vanetza::asn1::EccP256CurvePoint_to_EccPoint(*eccP256);
    return backend.decompress_point(ecc_point, curve_name);
}

boost::optional<ecdsa256::PublicKey> CertificateV3::get_encryption_public_key(Backend& backend) const
{
    auto unc = this->get_encryption_uncompressed_public_key(backend);
    if (unc) {
        return public_key_from_uncompressed(*unc);
    } else {
        return boost::none;
    }
}

size_t get_size(const CertificateVariant& certificate){
    struct canonical_visitor : public boost::static_visitor<size_t>
        {
            size_t operator()(const Certificate& cert) const
            {
                return get_size(cert);
            }
            size_t operator()(const CertificateV3& cert) const
            {
                // The get_size is not used in the V1.3.1
                return 0;
            }
        };
    return boost::apply_visitor(canonical_visitor(), certificate);
}

void serialize(OutputArchive& ar, const CertificateV3& certificate) {
    vanetza::ByteBuffer buffer = certificate.serialize();
    for (auto& temp_byte : buffer){
        ar << temp_byte;
    }
}

void serialize(OutputArchive& ar, const CertificateVariant& certificate){
    struct canonical_visitor : public boost::static_visitor<>
        {
            canonical_visitor(OutputArchive& ar): ar_(ar){}
            void operator()(const Certificate& cert) const
            {
                serialize(ar_, cert);
            }
            void operator()(const CertificateV3& cert) const
            {
                serialize(ar_, cert);
            }
            OutputArchive& ar_;
        };
    boost::apply_visitor(canonical_visitor(ar), certificate);
}

size_t deserialize(InputArchive& ar, const CertificateVariant& certificate){
    struct canonical_visitor : public boost::static_visitor<size_t>
        {
            canonical_visitor(InputArchive& ar): ar_(ar){}
            size_t operator()(const Certificate& cert) const
            {
                return deserialize(ar_, cert);
            }
            size_t operator()(const CertificateV3& cert) const
            {
                // Not used for V1.3.1
                return 0;
            }
            InputArchive& ar_;
        };
    return boost::apply_visitor(canonical_visitor(ar), certificate);
}

ByteBuffer convert_for_signing(const CertificateVariant& cert){
    struct canonical_visitor : public boost::static_visitor<ByteBuffer>
        {
            ByteBuffer operator()(const Certificate& cert) const
            {
                return convert_for_signing(cert);
            }
            ByteBuffer operator()(const CertificateV3& cert) const
            {
                return cert.convert_for_signing();
            }
        };
    return boost::apply_visitor(canonical_visitor(), cert);
}

boost::optional<Uncompressed> get_uncompressed_public_key(const CertificateVariant& certificate, Backend& backend){
    struct canonical_visitor : public boost::static_visitor<boost::optional<Uncompressed>>
        {
            canonical_visitor(Backend& backend): backend_(backend){}
            boost::optional<Uncompressed> operator()(const Certificate& cert) const
            {
                return get_uncompressed_public_key(cert, backend_);
            }
            boost::optional<Uncompressed> operator()(const CertificateV3& cert) const
            {
                //Not used in V1.3.1
                return boost::optional<Uncompressed>();
            }
            Backend& backend_;
        };
    return boost::apply_visitor(canonical_visitor(backend), certificate);
}

boost::optional<ecdsa256::PublicKey> get_public_key(const CertificateVariant& cert, Backend& backend)
{
    class canonical_visitor : public boost::static_visitor<boost::optional<ecdsa256::PublicKey>>
        {
            public:
                canonical_visitor(Backend& backend): backend_(backend){}
                boost::optional<ecdsa256::PublicKey> operator()(const Certificate& cert) const
                {
                    return get_public_key(cert, backend_);
                }
                boost::optional<ecdsa256::PublicKey> operator()(const CertificateV3& cert) const
                {
                    return cert.get_public_key(backend_);
                }
            private:
                Backend& backend_;

        };
    return boost::apply_visitor(canonical_visitor(backend), cert);
}

HashedId8 calculate_hash(const CertificateVariant& cert){
    struct canonical_visitor : public boost::static_visitor<HashedId8>
        {
            HashedId8 operator()(const Certificate& cert) const
            {
                return calculate_hash(cert);
            }
            HashedId8 operator()(const CertificateV3& cert) const
            {
                return cert.calculate_hash();
            }
        };
    return boost::apply_visitor(canonical_visitor(), cert);
}

ecdsa256::PublicKey public_key_from_uncompressed(const Uncompressed &unc)
{
    ecdsa256::PublicKey pub;
    if (unc.x.size() != pub.x.size() || unc.y.size() != pub.y.size()) {
        throw std::invalid_argument("Invalid uncompressed public key");
    }

    std::copy_n(unc.x.begin(), pub.x.size(), pub.x.data());
    std::copy_n(unc.y.begin(), pub.y.size(), pub.y.data());
    return pub;
}

} // ns security
} // ns vanetza
