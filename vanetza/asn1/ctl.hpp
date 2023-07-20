#ifndef Ctl_HPP_VUZG68JA
#define Ctl_HPP_VUZG68JA

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/ToBeSignedTlmCtl.h>
#include <vanetza/asn1/pki/ToBeSignedRcaCtl.h>


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

class ToBeSignedRcaCtl : public asn1c_oer_wrapper<ToBeSignedRcaCtl_t>
{
public:
    using wrapper = asn1c_oer_wrapper<ToBeSignedRcaCtl_t>;
    ToBeSignedRcaCtl() : wrapper(asn_DEF_ToBeSignedRcaCtl) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* Ctl_HPP_VUZG68JA */
