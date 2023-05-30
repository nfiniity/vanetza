#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <openssl/param_build.h>
#include <cassert>
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

// Generate random key pair on curve
EvpKey::EvpKey(const std::string &curve_name) : evpKey(EVP_EC_gen(curve_name.data()))
{
    check(evpKey);
}

// Convert from our public key format to OpenSSL EVP_PKEY
EvpKey::EvpKey(const ecdsa256::PublicKey &key, const std::string &curve_name): evpKey(nullptr)
{
    // Convert public key to OpenSSL import format
    std::array<uint8_t, 65> key_bytes;
    key_bytes[0] = POINT_CONVERSION_UNCOMPRESSED;
    std::copy(key.x.begin(), key.x.end(), key_bytes.begin() + 1);
    std::copy(key.y.begin(), key.y.end(), key_bytes.begin() + 33);

    // Set up parameters for EVP_PKEY_fromdata
    OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
    check(param_bld &&
          1 == OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", curve_name.data(), 0) &&
          1 == OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", key_bytes.data(), key_bytes.size()));
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
    check(params);

    // Import public key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    check(ctx &&
          1 == EVP_PKEY_fromdata_init(ctx) &&
          1 == EVP_PKEY_fromdata(ctx, &evpKey, EVP_PKEY_PUBLIC_KEY, params));

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

} // namespace openssl
} // namespace security
} // namespace vanetza
