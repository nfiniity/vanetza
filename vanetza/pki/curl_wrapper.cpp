#include <vanetza/pki/curl_wrapper.hpp>

namespace vanetza
{
namespace pki
{

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto *bb = static_cast<vanetza::ByteBuffer *>(userdata);
    bb->insert(bb->end(), ptr, ptr + size * nmemb);
    return size * nmemb;
}

CurlWrapper::CurlWrapper(const Runtime& runtime) : runtime(runtime)
{
    // Setup curl
    if (!curl) {
        throw std::runtime_error("curl_easy_init() failed");
    }
    // Use TLS 1.2 or higher
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    // Callback
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    // Set timeout
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 2000L);
}

CurlWrapper::~CurlWrapper()
{
    curl_easy_cleanup(curl);
}

boost::optional<ByteBuffer> CurlWrapper::get_data(const std::string& url)
{
    // Do not try to fetch data if last attempt failed less than 5 seconds ago
    if (runtime.now() - last_failure < std::chrono::seconds(5)) {
        return boost::none;
    }

    ByteBuffer bb;
    curl_easy_setopt(curl, CURLOPT_URL, url.data());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &bb);
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        return bb;
    }
    last_failure = runtime.now();
    return boost::none;
}

} // namespace pki
} // namespace vanetza
