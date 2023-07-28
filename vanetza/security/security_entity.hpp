#ifndef SECURITY_ENTITY_HPP
#define SECURITY_ENTITY_HPP

#include <vanetza/security/decap_confirm.hpp>
#include <vanetza/security/decap_request.hpp>
#include <vanetza/security/encap_confirm.hpp>
#include <vanetza/security/encap_request.hpp>

namespace vanetza
{
namespace security
{

using IdChangeCallback = std::function<void(const security::HashedId8&)>;
using IdChangeCallbackIterator = std::list<IdChangeCallback>::iterator;

class SecurityEntity
{
public:
    /**
     * \brief Creates a security envelope covering the given payload.
     *
     * The payload consists of the CommonHeader, ExtendedHeader and the payload of
     * the layers above the network layer. The entire security envelope is used
     * to calculate a signature which gets added to the resulting SecuredMessage.
     *
     * \param request containing payload to sign
     * \return confirmation containing signed SecuredMessage
     */
    virtual EncapConfirm encapsulate_packet(EncapRequest&& request) = 0;

    /**
     * \brief Decapsulates the payload within a SecuredMessage
     *
     * Verifies the Signature and SignerInfo of a SecuredMessage.
     *
     * \param request containing a SecuredMessage
     * \return decapsulation confirmation including plaintext payload
     */
    virtual DecapConfirm decapsulate_packet(DecapRequest&& request) = 0;

    virtual ~SecurityEntity() = default;

    /**
     * \brief Calls all registered ID change callbacks
     * \param new_id new ID
     */
    void change_id(const security::HashedId8 &new_id) const;

    /**
     * \brief Register a callback to be called when the ID changes
     * \param callback callback to register
     * \return iterator to the registered callback
     */
    IdChangeCallbackIterator register_id_change_callback(IdChangeCallback &&callback);

    /**
     * \brief Unregister a callback
     * \param it iterator to the callback to unregister
     */
    void unregister_id_change_callback(const IdChangeCallbackIterator &it);

private:
    // Use a list so iterators are not invalidated when a callback is removed
    std::list<IdChangeCallback> id_change_callbacks;
};

} // namespace security
} // namespace vanetza

#endif // SECURITY_ENTITY_HPP
