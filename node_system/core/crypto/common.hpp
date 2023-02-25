#pragma once
#include "../common/common.hpp"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/ecdh.h>
#include <openssl/sha.h>

namespace node_system::crypto
{
    class Key : public ByteArray
    {
    public:
        using ByteArray::ByteArray;
        using ByteArray::operator=;
        using ByteArray::operator[];
    };
    class KeyView : public ByteView
    {
    public:
        using ByteView::ByteView;
        using ByteView::operator=;
        using ByteView::operator[];
    };

    struct Hash
    {
        enum class HashType
        {
            SHA256,
            SHA384,
            SHA512
        };
        static constexpr const char* SHA256_NAME = "SHA256";
        static constexpr const char* SHA384_NAME = "SHA384";
        static constexpr const char* SHA512_NAME = "SHA512";

        static constexpr uint32_t SHA256_SIZE = SHA256_DIGEST_LENGTH;
        static constexpr uint32_t SHA384_SIZE = SHA384_DIGEST_LENGTH;
        static constexpr uint32_t SHA512_SIZE = SHA512_DIGEST_LENGTH;

        Hash(const ByteArray hash_value, const HashType hash) : hash_type{ hash }, hash_value{ hash_value } {}

        [[nodiscard]] uint32_t size() const { return static_cast<uint32_t>(hash_value.size()); }
        [[nodiscard]] auto data() const { return hash_value.data(); }
        [[nodiscard]] auto type() const { return hash_type; }

        template<typename T>
        [[nodiscard]] auto* as() const { return reinterpret_cast<const T*>(hash_value.data()); }
        [[nodiscard]] const uint8_t* as_uint8() const { return as<uint8_t>(); }

        const HashType hash_type;
        const ByteArray hash_value;
    };

    struct KeyPair
    {
        KeyPair(const Key private_key, const Key public_key) : private_key{ private_key }, public_key{ public_key } {}

        [[nodiscard]] auto get_public_key_view() const { return KeyView{ public_key.data(), public_key.size() }; }
        [[nodiscard]] auto get_private_key_view() const { return KeyView{ private_key.data(), private_key.size() }; }

        Key private_key;
        Key public_key;
    };

    template<typename T>
    struct OPENSSL_OBJECT_WRAPPER;
    template <>
    struct OPENSSL_OBJECT_WRAPPER<EVP_PKEY_CTX>
    {
        void operator() (EVP_PKEY_CTX* ptr) const { EVP_PKEY_CTX_free(ptr); }
    };
    template <>
    struct OPENSSL_OBJECT_WRAPPER<EVP_PKEY>
    {
        void operator() (EVP_PKEY* ptr) const { EVP_PKEY_free(ptr); }
    };
    template <>
    struct OPENSSL_OBJECT_WRAPPER<BIO>
    {
        void operator() (BIO* ptr) const { BIO_free_all(ptr); }
    };
    template <>
    struct OPENSSL_OBJECT_WRAPPER<EVP_CIPHER_CTX>
    {
        void operator() (EVP_CIPHER_CTX* ptr) const { EVP_CIPHER_CTX_free(ptr); }
    };

    using EVP_PKEY_CTX_WRAPPER = std::unique_ptr<EVP_PKEY_CTX, OPENSSL_OBJECT_WRAPPER<EVP_PKEY_CTX>>;
    using EVP_PKEY_WRAPPER = std::unique_ptr<EVP_PKEY, OPENSSL_OBJECT_WRAPPER<EVP_PKEY>>;
    using BIO_WRAPPER = std::unique_ptr<BIO, OPENSSL_OBJECT_WRAPPER<BIO>>;
    using EVP_CIPHER_CTX_WRAPPER = std::unique_ptr<EVP_CIPHER_CTX, OPENSSL_OBJECT_WRAPPER<EVP_CIPHER_CTX>>;
}