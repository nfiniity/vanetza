#ifndef EcSignature_HPP_IUGHG23A
#define EcSignature_HPP_IUGHG23A

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/EcSignature.h>


namespace vanetza
{
namespace asn1
{

class EcSignature : public asn1c_oer_wrapper<EcSignature_t>
{
public:
    using wrapper = asn1c_oer_wrapper<EcSignature_t>;
    EcSignature() : wrapper(asn_DEF_EcSignature) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* EcSignature_HPP_IUGHG23A */
