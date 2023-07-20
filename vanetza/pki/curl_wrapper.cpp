#include <vanetza/pki/curl_wrapper.hpp>
#include <iostream>

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
    // Fail on HTTP error codes
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
}

CurlWrapper::~CurlWrapper()
{
    curl_easy_cleanup(curl);
    curl_slist_free_all(its_request_headerlist);
}

boost::optional<ByteBuffer> CurlWrapper::get_data(const std::string& url)
{
    // Do not try to fetch data if last attempt failed less than 5 seconds ago
    if (runtime.now() - last_failure < std::chrono::seconds(5)) {
        return boost::none;
    }

    ByteBuffer bb;
    curl_easy_setopt(curl, CURLOPT_URL, url.data());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &bb);
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        return bb;
    }

    std::cout << "CurlWrapper::get_data() failed: " << curl_easy_strerror(res) << std::endl;
    last_failure = runtime.now();
    return boost::none;
}

curl_slist *create_its_request_headerlist()
{
    curl_slist *headerlist = nullptr;
    headerlist = curl_slist_append(headerlist, "Content-Type: application/x-its-request");
    return headerlist;
}

boost::optional<ByteBuffer>
CurlWrapper::post_its_request(const std::string &url, const ByteBuffer &data)
{
    // Do not try to fetch data if last attempt failed less than 5 seconds ago
    if (runtime.now() - last_failure < std::chrono::seconds(5)) {
        return boost::none;
    }

    struct curl_slist *headerlist = nullptr;
    headerlist = curl_slist_append(headerlist, "Content-Type: application/x-its-request");

    ByteBuffer bb;
    curl_easy_setopt(curl, CURLOPT_URL, url.data());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &bb);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, data.size());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.data());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, nullptr);
    if (res == CURLE_OK) {
        return bb;
    }

    std::cout << "CurlWrapper::post_its_request() failed: " << curl_easy_strerror(res) << std::endl;
    last_failure = runtime.now();
    return boost::none;
}

} // namespace pki
} // namespace vanetza
