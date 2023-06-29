#ifndef PublicVerificationKey_HPP_87ZZC12P
#define PublicVerificationKey_HPP_87ZZC12P

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/PublicVerificationKey.h>


namespace vanetza
{
namespace asn1
{

class PublicVerificationKey : public asn1c_oer_wrapper<PublicVerificationKey_t>
{
public:
    using wrapper = asn1c_oer_wrapper<PublicVerificationKey_t>;
    PublicVerificationKey() : wrapper(asn_DEF_PublicVerificationKey) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* PublicVerificationKey_HPP_87ZZC12P */
