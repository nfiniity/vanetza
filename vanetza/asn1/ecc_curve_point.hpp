#ifndef EccCurvePoint_HPP_1DCXVV78
#define EccCurvePoint_HPP_1DCXVV78

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/EccP256CurvePoint.h>
#include <vanetza/asn1/pki/EccP384CurvePoint.h>


namespace vanetza
{
namespace asn1
{

class EccP256CurvePoint : public asn1c_oer_wrapper<EccP256CurvePoint_t>
{
public:
    using wrapper = asn1c_oer_wrapper<EccP256CurvePoint_t>;
    EccP256CurvePoint() : wrapper(asn_DEF_EccP256CurvePoint) {}
};

class EccP384CurvePoint : public asn1c_oer_wrapper<EccP384CurvePoint_t>
{
public:
    using wrapper = asn1c_oer_wrapper<EccP384CurvePoint_t>;
    EccP384CurvePoint() : wrapper(asn_DEF_EccP384CurvePoint) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* EccCurvePoint_HPP_1DCXVV78 */
