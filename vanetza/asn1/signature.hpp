#ifndef Signature_HPP_U2Z13251
#define Signature_HPP_U2Z13251

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/Signature.h>


namespace vanetza
{
namespace asn1
{

class Signature : public asn1c_oer_wrapper<Signature_t>
{
public:
    using wrapper = asn1c_oer_wrapper<Signature_t>;
    Signature() : wrapper(asn_DEF_Signature) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* Signature_HPP_U2Z13251 */
