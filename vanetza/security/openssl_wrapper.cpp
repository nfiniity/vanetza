#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <openssl/param_build.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <cassert>
#include <fstream>
#include "openssl_wrapper.hpp"

namespace vanetza
{
namespace security
{
namespace openssl
{

void check(bool valid)
{
    if (!valid) {
        throw Exception();
    }
}

Exception::Exception() : Exception(ERR_get_error())
{
}

Exception::Exception(code_type err) :
    std::runtime_error(ERR_reason_error_string(err))
{
}

BigNumber::BigNumber() : bignum(BN_new())
{
    check(bignum != nullptr);
}

BigNumber::BigNumber(const uint8_t* arr, std::size_t len) : BigNumber()
{
    BN_bin2bn(arr, len, bignum);
}

BIGNUM* BigNumber::move()
{
    BIGNUM* ptr = nullptr;
    std::swap(ptr, bignum);
    return ptr;
}

BigNumber::~BigNumber()
{
    if (bignum) {
        BN_clear_free(bignum);
    }
}

BigNumberContext::BigNumberContext() : ctx(BN_CTX_new())
{
    check(ctx != nullptr);
    BN_CTX_start(ctx);
}

BigNumberContext::~BigNumberContext()
{
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

Point::Point(const EC_GROUP* group) : point(EC_POINT_new(group))
{
    check(point != nullptr);
}

Point::~Point()
{
    EC_POINT_free(point);
}

Group::Group(int nid) : group(EC_GROUP_new_by_curve_name(nid))
{
    check(group != nullptr);
}

Group::~Group()
{
    EC_GROUP_clear_free(group);
}

Signature::Signature(ECDSA_SIG* sig) : signature(sig)
{
    check(signature);
}

Signature::Signature(const EcdsaSignature& ecdsa) : signature(ECDSA_SIG_new())
{
    check(signature);
#if OPENSSL_API_COMPAT < 0x10100000L
    const ByteBuffer r = convert_for_signing(ecdsa.R);
    BN_bin2bn(r.data(), r.size(), signature->r);
    BN_bin2bn(ecdsa.s.data(), ecdsa.s.size(), signature->s);
#else
    BigNumber bn_r { convert_for_signing(ecdsa.R) };
    BigNumber bn_s { ecdsa.s };
    // ownership of big numbers is transfered by calling ECDSA_SIG_set0!
    ECDSA_SIG_set0(signature, bn_r.move(), bn_s.move());
#endif
}

Signature::~Signature()
{
    ECDSA_SIG_free(signature);
}

Key::Key() : eckey(EC_KEY_new())
{
    check(eckey);
}

Key::Key(int nid) : eckey(EC_KEY_new_by_curve_name(nid))
{
    check(eckey);
}

Key::Key(Key&& other) : eckey(nullptr)
{
    std::swap(eckey, other.eckey);
}

Key& Key::operator=(Key&& other)
{
    std::swap(eckey, other.eckey);
    return *this;
}

Key::~Key()
{
    EC_KEY_free(eckey);
}

EvpKey::EvpKey() : evpKey(EVP_PKEY_new())
{
    check(evpKey);
}

EvpKey::EvpKey(EVP_PKEY *key) : evpKey(key)
{
    check(evpKey);
}

// Convert from our public key format to OpenSSL EVP_PKEY
EvpKey::EvpKey(const std::string &curve_name,
               const boost::optional<ecdsa256::PrivateKey> &priv_key,
               const boost::optional<ecdsa256::PublicKey> &pub_key) : evpKey(nullptr)
{
    // If no public or private key is given, generate a new key pair
    if (!pub_key && !priv_key) {
        evpKey = EVP_EC_gen(curve_name.data());
        return;
    }

    // Set up parameters for EVP_PKEY_fromdata
    OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
    check(param_bld &&
          1 == OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", curve_name.data(), 0));

    std::unique_ptr<BigNumber> bn_priv_key;
    if (priv_key) {
        bn_priv_key.reset(new BigNumber(priv_key->key));
        check(1 == OSSL_PARAM_BLD_push_BN(param_bld, "priv", *bn_priv_key));
    }

    std::array<uint8_t, 65> key_bytes;
    if (pub_key) {
        // Convert PublicKey to OpenSSL import format
        key_bytes[0] = POINT_CONVERSION_UNCOMPRESSED;
        std::copy(pub_key->x.begin(), pub_key->x.end(), key_bytes.begin() + 1);
        std::copy(pub_key->y.begin(), pub_key->y.end(), key_bytes.begin() + 33);
    } else {
        // Compute public key from private key
        int group_nid = OBJ_sn2nid(curve_name.data());
        check(group_nid != NID_undef);

        Group group(group_nid);
        Point point(group);
        check(1 == EC_POINT_mul(group, point, *bn_priv_key, nullptr, nullptr, nullptr) &&
              0 < EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                     key_bytes.data(), key_bytes.size(), nullptr));
    }
    openssl::check(1 == OSSL_PARAM_BLD_push_octet_string(param_bld, "pub",
                                                         key_bytes.data(),
                                                         key_bytes.size()));

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
    check(params);

    // Import public key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    check(ctx &&
          1 == EVP_PKEY_fromdata_init(ctx) &&
          1 == EVP_PKEY_fromdata(ctx, &evpKey, priv_key ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params));

    // Check public key
    EVP_PKEY_CTX *check_ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, evpKey, nullptr);
    check(1 == EVP_PKEY_public_check(check_ctx));

    // Clean up
    EVP_PKEY_CTX_free(check_ctx);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(params);
}

EvpKey::EvpKey(EvpKey &&other) : evpKey(nullptr)
{
    std::swap(evpKey, other.evpKey);
}

EvpKey& EvpKey::operator=(EvpKey&& other)
{
    std::swap(evpKey, other.evpKey);
    return *this;
}

EvpKey::~EvpKey()
{
    EVP_PKEY_free(evpKey);
}

std::string EvpKey::group_name() const
{
    std::string group_name;
    size_t group_name_size;

    // Get size of group name
    EVP_PKEY_get_group_name(evpKey, nullptr, 0, &group_name_size);
    group_name.resize(group_name_size);

    EVP_PKEY_get_group_name(evpKey, &group_name[0], group_name_size, nullptr);
    return group_name;
}

// Convert from OpenSSL EVP_PKEY to our public key format
ecdsa256::PublicKey EvpKey::public_key() const
{
    ecdsa256::PublicKey key;
    std::array<uint8_t, 65> out_buf;
    size_t out_len;

    check(1 == EVP_PKEY_set_utf8_string_param(evpKey, "point-format", "uncompressed") &&
          1 == EVP_PKEY_get_octet_string_param(evpKey, "pub", out_buf.data(), out_buf.size(), &out_len));
    assert(out_len == out_buf.size());
    assert(out_buf[0] == POINT_CONVERSION_UNCOMPRESSED);

    std::copy(out_buf.begin() + 1, out_buf.begin() + 33, key.x.begin());
    std::copy(out_buf.begin() + 33, out_buf.begin() + 65, key.y.begin());

    return key;
}

ecdsa256::PrivateKey EvpKey::private_key() const
{
    ecdsa256::PrivateKey key;
    BIGNUM *private_number = nullptr;

    check(1 == EVP_PKEY_get_bn_param(evpKey, "priv", &private_number) &&
          BN_num_bytes(private_number) == key.key.size() &&
          BN_bn2bin(private_number, key.key.data()));

    BN_clear_free(private_number);
    return key;
}

EccCurvePointVariant EvpKey::ecc_curve_point() const {
    // Get public key in compressed format
    size_t out_len;

    check(1 == EVP_PKEY_set_utf8_string_param(evpKey, "point-format", "compressed") &&
          1 == EVP_PKEY_get_octet_string_param(evpKey, "pub", nullptr, 0, &out_len));

    ByteBuffer compressed_key(out_len);
    check(1 == EVP_PKEY_get_octet_string_param(evpKey, "pub", compressed_key.data(), compressed_key.size(), nullptr));
    assert(out_len == compressed_key.size());

    bool compressed_y_0 = compressed_key[0] == 0x02;
    bool compressed_y_1 = compressed_key[0] == 0x03;
    assert(compressed_y_0 || compressed_y_1);

    OCTET_STRING_t *x = nullptr;
    EccCurvePointVariant ecc_curve_point;

    if (out_len == 33) {
        asn1::EccP256CurvePoint ecc_p256_curve_point;

        int choice = compressed_y_0 ? EccP256CurvePoint_PR_compressed_y_0 : EccP256CurvePoint_PR_compressed_y_1;
        CHOICE_variant_set_presence(&asn_DEF_EccP256CurvePoint, &(*ecc_p256_curve_point), choice);
        if (compressed_y_0) {
            x = &ecc_p256_curve_point->choice.compressed_y_0;
        } else {
            x = &ecc_p256_curve_point->choice.compressed_y_1;
        }

        ecc_curve_point = std::move(ecc_p256_curve_point);
    } else if (out_len == 49) {
        asn1::EccP384CurvePoint ecc_p384_curve_point;

        int choice = compressed_y_0 ? EccP384CurvePoint_PR_compressed_y_0 : EccP384CurvePoint_PR_compressed_y_1;
        CHOICE_variant_set_presence(&asn_DEF_EccP384CurvePoint, &(*ecc_p384_curve_point), choice);
        if (compressed_y_0) {
            x = &ecc_p384_curve_point->choice.compressed_y_0;
        } else {
            x = &ecc_p384_curve_point->choice.compressed_y_1;
        }

        ecc_curve_point = std::move(ecc_p384_curve_point);
    } else {
        throw std::runtime_error("Invalid public key length");
    }

    OCTET_STRING_fromBuf(x, reinterpret_cast<const char*>(&compressed_key[1]), compressed_key.size() - 1);

    return ecc_curve_point;
}

asn1::PublicVerificationKey EvpKey::public_verification_key() const
{
    asn1::PublicVerificationKey public_verification_key_wrapper;
    PublicVerificationKey_t &public_verification_key = *public_verification_key_wrapper;

    EccCurvePointVariant ecc_curve_point = this->ecc_curve_point();
    std::string own_group_name = group_name();
    if (own_group_name == "prime256v1") {
        CHOICE_variant_set_presence(&asn_DEF_PublicVerificationKey,
                                    &public_verification_key,
                                    PublicVerificationKey_PR_ecdsaNistP256);
        auto &ecc_p256_curve_point = boost::get<asn1::EccP256CurvePoint>(ecc_curve_point);
        std::swap(public_verification_key.choice.ecdsaNistP256, *ecc_p256_curve_point);
    } else if (own_group_name == "brainpoolP256r1") {
        CHOICE_variant_set_presence(&asn_DEF_PublicVerificationKey,
                                    &public_verification_key,
                                    PublicVerificationKey_PR_ecdsaBrainpoolP256r1);
        auto &ecc_p256_curve_point = boost::get<asn1::EccP256CurvePoint>(ecc_curve_point);
        std::swap(public_verification_key.choice.ecdsaBrainpoolP256r1, *ecc_p256_curve_point);
    } else if (own_group_name == "brainpoolP384r1") {
        CHOICE_variant_set_presence(&asn_DEF_PublicVerificationKey,
                                    &public_verification_key,
                                    PublicVerificationKey_PR_ecdsaBrainpoolP384r1);
        auto &ecc_p384_curve_point = boost::get<asn1::EccP384CurvePoint>(ecc_curve_point);
        std::swap(public_verification_key.choice.ecdsaBrainpoolP384r1, *ecc_p384_curve_point);
    } else {
        throw std::domain_error("Unsupported EC group");
    }

    return public_verification_key_wrapper;
}

void EvpKey::write_private_key(const std::string &filename) const
{
    write_key(filename, EVP_PKEY_KEYPAIR);
}

void EvpKey::write_public_key(const std::string &filename) const
{
    write_key(filename, EVP_PKEY_PUBLIC_KEY);
}

void EvpKey::write_key(const std::string &file_name, int type) const
{
    FILE *fp = fopen(file_name.data(), "wb");

    if (fp == nullptr) {
        throw std::runtime_error("Could not open file");
    }

    OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(evpKey, EVP_PKEY_KEYPAIR, "DER", nullptr, nullptr);
    vanetza::security::openssl::check(ectx != nullptr &&
                                      1 == OSSL_ENCODER_to_fp(ectx, fp));

    fclose(fp);
}

EvpKey EvpKey::read_key(const std::string &filename) {
    EVP_PKEY *pkey = nullptr;
    FILE *fp = fopen(filename.data(), "rb");

    if (fp == nullptr) {
        throw std::runtime_error("Could not open file");
    }

    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", nullptr, "EC", 0, nullptr, nullptr);
    openssl::check(dctx != nullptr && 1 == OSSL_DECODER_from_fp(dctx, fp));

    fclose(fp);

    return EvpKey(pkey);
}

} // namespace openssl
} // namespace security
} // namespace vanetza
