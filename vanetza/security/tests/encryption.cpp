#include <gtest/gtest.h>
#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/common/byte_buffer.hpp>

using namespace vanetza::security;

TEST(Encryption, CcmEncryption)
{
    BackendOpenSsl backend;
    std::array<uint8_t, 16> aes_key {{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                       0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                       0x0c, 0x0d, 0x0e, 0x0f }};
    std::array<uint8_t, 12> aes_nonce {{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                         0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b }};
    vanetza::ByteBuffer data {{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b }};


    vanetza::ByteBuffer encrypted_data;
    vanetza::ByteBuffer encrypted_data_tag;

    backend.ccm_encrypt(data, aes_key, aes_nonce, encrypted_data, encrypted_data_tag);

    EXPECT_EQ(encrypted_data.size(), data.size());
    EXPECT_EQ(encrypted_data_tag.size(), 12);
}
