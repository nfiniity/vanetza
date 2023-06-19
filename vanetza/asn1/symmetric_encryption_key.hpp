#ifndef SymmetricEncryptionKey_HPP_IADV398L
#define SymmetricEncryptionKey_HPP_IADV398L

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/SymmetricEncryptionKey.h>


namespace vanetza
{
namespace asn1
{

class SymmetricEncryptionKey : public asn1c_oer_wrapper<SymmetricEncryptionKey_t>
{
public:
    using wrapper = asn1c_oer_wrapper<SymmetricEncryptionKey_t>;
    SymmetricEncryptionKey() : wrapper(asn_DEF_SymmetricEncryptionKey) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* SymmetricEncryptionKey_HPP_IADV398L */
