#include <vanetza/security/basic_elements.hpp>
#include <vanetza/asn1/support/OCTET_STRING.h>
#include <vanetza/common/byte_buffer.hpp>
#include <algorithm>
#include <cassert>
#include <chrono>

namespace vanetza
{
namespace security
{

HashedId3 truncate(const HashedId8& in)
{
    HashedId3 out;
    assert(out.size() <= in.size());
    std::copy_n(in.rbegin(), out.size(), out.rbegin());
    return out;
}

Time32 convert_time32(const Clock::time_point& tp)
{
    using std::chrono::duration_cast;
    using seconds = std::chrono::duration<Time32>;
    return duration_cast<seconds>(tp.time_since_epoch()).count();
}

Clock::time_point convert_time_point(const Time32& t)
{
    using std::chrono::duration_cast;
    using seconds = std::chrono::duration<Time32>;
    return Clock::time_point { duration_cast<Clock::duration>(seconds(t)) };
}

Clock::time_point convert_time_point(const Time64& t)
{
    using std::chrono::duration_cast;
    using microseconds = std::chrono::duration<Time64, std::micro>;
    return Clock::time_point { duration_cast<Clock::duration>(microseconds(t)) };
}

Time64 convert_time64(const Clock::time_point& tp)
{
    using std::chrono::duration_cast;
    using microseconds = std::chrono::duration<Time64, std::micro>;
    return duration_cast<microseconds>(tp.time_since_epoch()).count();
}


} // namespace security
} // namespace vanetza
