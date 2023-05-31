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
    std::array<uint8_t, 12> encrypted_data_tag;

    backend.ccm_encrypt(data, aes_key, aes_nonce, encrypted_data, encrypted_data_tag);

    EXPECT_EQ(encrypted_data.size(), data.size());
}

TEST(Encryption, EncryptService)
{
    BackendOpenSsl backend;
    ecdsa256::PublicKey public_key;
    public_key.x = {0xcf, 0x20, 0xfb, 0x9a, 0x1d, 0x11, 0x6c, 0x5e,
                    0x9f, 0xec, 0x38, 0x87, 0x6c, 0x1d, 0x2f, 0x58,
                    0x47, 0xab, 0xa3, 0x9b, 0x79, 0x23, 0xe6, 0xeb,
                    0x94, 0x6f, 0x97, 0xdb, 0xa3, 0x7d, 0xbd, 0xe5};
    public_key.y = {0x26, 0xca, 0x07, 0x17, 0x8d, 0x26, 0x75, 0xff,
                    0xcb, 0x8e, 0xb6, 0x84, 0xd0, 0x24, 0x02, 0x25,
                    0x8f, 0xb9, 0x33, 0x6e, 0xcf, 0x12, 0x16, 0x2f,
                    0x5c, 0xcd, 0x86, 0x71, 0xa8, 0xbf, 0x1a, 0x47};
    std::string curve_name = "prime256v1";
    vanetza::ByteBuffer data {{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b }};

    backend.encrypt_data(public_key, curve_name, data);
}
