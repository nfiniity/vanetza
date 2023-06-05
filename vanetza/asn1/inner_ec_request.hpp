#ifndef InnerEcRequest_HPP_7XJXDJZL
#define InnerEcRequest_HPP_7XJXDJZL

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/InnerEcRequest.h>


namespace vanetza
{
namespace asn1
{

class InnerEcRequest : public asn1c_oer_wrapper<InnerEcRequest_t>
{
public:
    using wrapper = asn1c_oer_wrapper<InnerEcRequest_t>;
    InnerEcRequest() : wrapper(asn_DEF_InnerEcRequest) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* InnerEcRequest_HPP_7XJXDJZL */
