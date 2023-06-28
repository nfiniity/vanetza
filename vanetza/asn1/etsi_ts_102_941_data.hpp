#ifndef EtsiTs102941Data_HPP_81YAE7CA
#define EtsiTs102941Data_HPP_81YAE7CA

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/EtsiTs102941Data.h>


namespace vanetza
{
namespace asn1
{

class EtsiTs102941Data : public asn1c_oer_wrapper<EtsiTs102941Data_t>
{
public:
    using wrapper = asn1c_oer_wrapper<EtsiTs102941Data_t>;
    EtsiTs102941Data() : wrapper(asn_DEF_EtsiTs102941Data) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* EtsiTs102941Data_HPP_81YAE7CA */
