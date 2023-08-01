#ifndef Crl_HPP_OCC24XAP
#define Crl_HPP_OCC24XAP

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/ToBeSignedCrl.h>


namespace vanetza
{
namespace asn1
{

class ToBeSignedCrl : public asn1c_oer_wrapper<ToBeSignedCrl_t>
{
public:
    using wrapper = asn1c_oer_wrapper<ToBeSignedCrl_t>;
    ToBeSignedCrl() : wrapper(asn_DEF_ToBeSignedCrl) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* Crl_HPP_OCC24XAP */
