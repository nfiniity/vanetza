#include <vanetza/security/security_entity.hpp>

namespace vanetza
{
namespace security
{

void SecurityEntity::change_id(const security::HashedId8 &new_id) const
{
    for (const auto& callback : id_change_callbacks) {
        callback(new_id);
    }
}

IdChangeCallbackIterator SecurityEntity::register_id_change_callback(IdChangeCallback &&callback)
{
    return id_change_callbacks.insert(id_change_callbacks.end(), std::move(callback));
}

void SecurityEntity::unregister_id_change_callback(const IdChangeCallbackIterator &it)
{
    id_change_callbacks.erase(it);
}

} // namespace security
} // namespace vanetza
