#pragma once
#include "../common/common.hpp"

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
        KeyPair(const Key private_key, const Key public_key) : private_key{ private_key }, public_key{public_key} {}

        [[nodiscard]] auto get_public_key_view() const { return KeyView{ public_key.data(), public_key.size() }; }
        [[nodiscard]] auto get_private_key_view() const { return KeyView{private_key.data(), private_key.size() }; }

        Key private_key;
        Key public_key;
    };
    

}