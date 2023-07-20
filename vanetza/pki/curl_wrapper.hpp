#ifndef CURL_WRAPPER_HPP_AAB83LP1
#define CURL_WRAPPER_HPP_AAB83LP1

#include <curl/curl.h>
#include <boost/optional.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/runtime.hpp>
#include <list>
#include <map>

namespace vanetza
{
namespace pki
{

curl_slist *create_its_request_headerlist();

class CurlWrapper
{
public:
    CurlWrapper(const Runtime &);
    ~CurlWrapper();

    boost::optional<ByteBuffer> get_data(const std::string &url);

    boost::optional<ByteBuffer> post_its_request(const std::string &url,
                                          const ByteBuffer &data);

  private:
    CURL *curl = curl_easy_init();
    Clock::time_point last_failure;
    const Runtime &runtime;
    curl_slist *its_request_headerlist = create_its_request_headerlist();
};

} // namespace pki
} // namespace vanetza

#endif /* CURL_WRAPPER_HPP_AAB83LP1 */
