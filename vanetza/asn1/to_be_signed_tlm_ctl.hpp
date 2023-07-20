#ifndef ToBeSignedTlmCtl_HPP_VUZG68JA
#define ToBeSignedTlmCtl_HPP_VUZG68JA

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/ToBeSignedTlmCtl.h>


namespace vanetza
{
namespace asn1
{

class ToBeSignedTlmCtl : public asn1c_oer_wrapper<ToBeSignedTlmCtl_t>
{
public:
    using wrapper = asn1c_oer_wrapper<ToBeSignedTlmCtl_t>;
    ToBeSignedTlmCtl() : wrapper(asn_DEF_ToBeSignedTlmCtl) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* ToBeSignedTlmCtl_HPP_VUZG68JA */
