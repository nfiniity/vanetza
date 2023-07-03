#ifndef SharedAtRequest_HPP_01FCG23I
#define SharedAtRequest_HPP_01FCG23I

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/SharedAtRequest.h>


namespace vanetza
{
namespace asn1
{

class SharedAtRequest : public asn1c_oer_wrapper<SharedAtRequest_t>
{
public:
    using wrapper = asn1c_oer_wrapper<SharedAtRequest_t>;
    SharedAtRequest() : wrapper(asn_DEF_SharedAtRequest) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* SharedAtRequest_HPP_01FCG23I */
