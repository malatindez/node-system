#pragma once
#include "common.hpp"
#include "../utils/utils.hpp"
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

namespace node_system::crypto::SHA
{
    Hash ComputeHash(const ByteView data, const Hash::HashType hash_type)
    {
        ByteArray result;
        switch (hash_type)
        {
        case Hash::HashType::SHA256:
        {
            result.resize(SHA256_DIGEST_LENGTH);
            SHA256(data.as<const unsigned char>(), data.size(), result.as<unsigned char>());
            break;
        }
        case Hash::HashType::SHA384:
        {
            result.resize(SHA384_DIGEST_LENGTH);
            SHA384(data.as<const unsigned char>(), data.size(), result.as<unsigned char>());
            break;
        }
        case Hash::HashType::SHA512:
        {
            result.resize(SHA512_DIGEST_LENGTH);
            SHA512(data.as<const unsigned char>(), data.size(), result.as<unsigned char>());
            break;
        }
        default:
            utils::AlwaysAssert(false, "Unknown hash type");
        }
        return Hash{ result, hash_type };
    }
}