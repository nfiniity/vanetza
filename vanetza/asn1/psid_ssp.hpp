#ifndef PsidSsp_HPP_ZH72CDA0
#define PsidSsp_HPP_ZH72CDA0

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/PsidSsp.h>
#include <vanetza/asn1/pki/SequenceOfPsidSsp.h>


namespace vanetza
{
namespace asn1
{

class SequenceOfPsidSsp : public asn1c_oer_wrapper<SequenceOfPsidSsp_t>
{
public:
    using wrapper = asn1c_oer_wrapper<SequenceOfPsidSsp_t>;
    SequenceOfPsidSsp() : wrapper(asn_DEF_SequenceOfPsidSsp) {}
};

class SequenceOfPsidSspXml : public asn1c_xer_wrapper<SequenceOfPsidSsp_t>
{
public:
    using wrapper = asn1c_xer_wrapper<SequenceOfPsidSsp_t>;
    SequenceOfPsidSspXml() : wrapper(asn_DEF_SequenceOfPsidSsp) {}
};

class PsidSsp : public asn1c_oer_wrapper<PsidSsp_t>
{
public:
    using wrapper = asn1c_oer_wrapper<PsidSsp_t>;
    PsidSsp() : wrapper(asn_DEF_PsidSsp) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* PsidSsp_HPP_ZH72CDA0 */
