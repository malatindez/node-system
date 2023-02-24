#pragma once
#include "common.hpp"
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include "sha.hpp"

namespace node_system::crypto::ECDSA
{
    int GetCurveByName(const std::string_view curve)
    {
        if (curve == "secp256k1")
        {
            return NID_secp256k1;
        }
        else if (curve == "secp384r1")
        {
            return NID_secp384r1;
        }
        else if (curve == "secp521r1")
        {
            return NID_secp521r1;
        }
        else
        {
            throw std::runtime_error("Unknown curve type");
        }
    }


    class KeyPairGenerator : utils::non_copyable_movable
    {
        public:
            explicit KeyPairGenerator(const int curve_id)
            {               
                ctx_ = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
                utils::AlwaysAssert(ctx_ != nullptr, "EVP_PKEY_CTX_new_id() failed");
                utils::AlwaysAssert(EVP_PKEY_keygen_init(ctx_) > 0, "EVP_PKEY_keygen_init() failed");
                utils::AlwaysAssert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_, curve_id) > 0, "EVP_PKEY_CTX_set_ec_paramgen_curve_nid() failed");
            }
            explicit KeyPairGenerator(const std::string_view curve_name) : KeyPairGenerator(GetCurveByName(curve_name)) { }
            ~KeyPairGenerator()
            {
                EVP_PKEY_CTX_free(ctx_);
            }

            [[nodiscard]] KeyPair generate() const
            { 
                EVP_PKEY *pkey = nullptr;
                utils::AlwaysAssert(EVP_PKEY_keygen(ctx_, &pkey) > 0, "EVP_PKEY_keygen() failed");
                unsigned char* key_data;
                unsigned long key_size;


                BIO* bio = BIO_new(BIO_s_mem());
                utils::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
                utils::AlwaysAssert(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) > 0, "PEM_write_bio_PrivateKey() failed");
                key_size = BIO_get_mem_data(bio, &key_data);

                Key private_key;
                private_key.resize(key_size);
                std::copy_n(key_data, key_size, private_key.as<unsigned char>());
                BIO_free_all(bio);

                

                bio = BIO_new(BIO_s_mem());
                utils::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
                utils::AlwaysAssert(PEM_write_bio_PUBKEY(bio, pkey) > 0, "PEM_write_bio_PUBKEY() failed");
                key_size = BIO_get_mem_data(bio, &key_data);
                Key public_key;
                public_key.resize(key_size);
                std::copy_n(key_data, key_size, public_key.as<unsigned char>());
                BIO_free_all(bio);

                EVP_PKEY_free(pkey);
                return KeyPair{ private_key, public_key };
            }        
        
    private:
        EVP_PKEY_CTX *ctx_ = nullptr;
    };

    class Signer : utils::non_copyable_movable
    {
    public:
        Signer(const KeyView private_key, const Hash::HashType hash_type) : hash_type_(hash_type)
        {
            BIO* bio = BIO_new_mem_buf(private_key.data(), static_cast<int>(private_key.size()));
            utils::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
            pkey_ = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            utils::AlwaysAssert(pkey_ != nullptr, "PEM_read_bio_PrivateKey() failed");
            BIO_free(bio);

            ctx_ = EVP_PKEY_CTX_new(pkey_, nullptr);
            utils::AlwaysAssert(ctx_ != nullptr, "EVP_PKEY_CTX_new() failed");
            utils::AlwaysAssert(EVP_PKEY_sign_init(ctx_) > 0, "EVP_PKEY_sign_init() failed");
            if (hash_type == Hash::HashType::SHA256)
            {
                utils::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_, EVP_sha256()) > 0, "EVP_PKEY_CTX_set_signature_md() failed");
            }
            else if (hash_type == Hash::HashType::SHA384)
            {
                utils::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_, EVP_sha384()) > 0, "EVP_PKEY_CTX_set_signature_md() failed");
            }
            else if (hash_type == Hash::HashType::SHA512)
            {
                utils::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_, EVP_sha512()) > 0, "EVP_PKEY_CTX_set_signature_md() failed");
            }
            else
            {
                utils::AlwaysAssert(false, "Unsupported hash type");
            }
        }

        ~Signer()
        {
            EVP_PKEY_CTX_free(ctx_);
            EVP_PKEY_free(pkey_);
        }

        [[nodiscard]] ByteArray sign_hash(const Hash hash) const
        {
            utils::Assert(hash.hash_type == hash_type_, "Unsupported hash type");

            size_t signature_size = 0;
            ByteArray signature;

            utils::AlwaysAssert(EVP_PKEY_sign(ctx_, nullptr, &signature_size, hash.as_uint8(), hash.size()) > 0, "EVP_PKEY_sign() failed");
            signature.resize(signature_size);

            utils::AlwaysAssert(EVP_PKEY_sign(ctx_, signature.as<unsigned char>(), &signature_size, hash.as_uint8(), hash.size()) > 0, "EVP_PKEY_sign() failed");
            signature.resize(signature_size);
            return signature;
        }

        [[nodiscard]] ByteArray sign_data(const ByteView data) const
        {
            const Hash hash = SHA::ComputeHash(data, hash_type_);
            return sign_hash(hash);
        }

    private:
        EVP_PKEY_CTX* ctx_ = nullptr;
        EVP_PKEY* pkey_ = nullptr;
        const Hash::HashType hash_type_;
    };

    class Verifier : utils::non_copyable_movable
    {
        public:
            Verifier(const KeyView public_key, const Hash::HashType hash_type) : hash_type_(hash_type)
            {
                BIO *bio = BIO_new_mem_buf(public_key.data(), static_cast<int>(public_key.size()));
                utils::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
                pkey_  = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
                utils::AlwaysAssert(pkey_  != nullptr, "PEM_read_bio_PUBKEY() failed");
                BIO_free(bio);
                
                ctx_ = EVP_PKEY_CTX_new(pkey_ , nullptr);
                utils::AlwaysAssert(ctx_ != nullptr, "EVP_PKEY_CTX_new() failed");
                utils::AlwaysAssert(EVP_PKEY_verify_init(ctx_) > 0, "EVP_PKEY_verify_init() failed");
                if (hash_type == Hash::HashType::SHA256)
                {
                    utils::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_, EVP_sha256()) > 0, "EVP_PKEY_CTX_set_signature_md() failed");
                }
                else if (hash_type == Hash::HashType::SHA384)
                {
                    utils::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_, EVP_sha384()) > 0, "EVP_PKEY_CTX_set_signature_md() failed");
                }
                else if (hash_type == Hash::HashType::SHA512)
                {
                    utils::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_, EVP_sha512()) > 0, "EVP_PKEY_CTX_set_signature_md() failed");
                }
                else
                {
                    utils::AlwaysAssert(false, "Unsupported hash type");
                }
            }

            ~Verifier()
            {
                EVP_PKEY_CTX_free(ctx_);
                EVP_PKEY_free(pkey_);
            }

            [[nodiscard]] bool verify_hash(const Hash hash, const ByteView signature) const
            {
                utils::Assert(hash.hash_type == hash_type_, "Unsupported hash type");

                return EVP_PKEY_verify(ctx_, signature.as<unsigned char>(), signature.size(), hash.as_uint8(), hash.size()) > 0;
            }

            [[nodiscard]] bool verify_data(const ByteView data, const ByteView signature) const
            {
                const Hash hash = SHA::ComputeHash(data, hash_type_);
                return verify_hash(hash, signature);
            }

        private:
            EVP_PKEY_CTX *ctx_ = nullptr;
            EVP_PKEY* pkey_ = nullptr;
            const Hash::HashType hash_type_;
    };
    [[deprecated]]
    [[nodiscard]] KeyPair generate_key_pair(std::string curve_name)
    {
        KeyPairGenerator instance(curve_name);
        return instance.generate();
    }
    
    [[deprecated]]
    [[nodiscard]] ByteArray sign_data(const KeyView private_key, const ByteView data, const Hash::HashType hash_type)
    {
        Signer instance(private_key, hash_type);
        return instance.sign_data(data);
    }
    [[deprecated]]
    [[nodiscard]] ByteArray sign_hash(const KeyView private_key, const Hash hash)
    {
        Signer instance(private_key, hash.hash_type);
        return instance.sign_hash(hash);
    }
    [[deprecated]]
    [[nodiscard]] bool verify_data(const KeyView public_key, const ByteView data, const ByteView signature, const Hash::HashType hash_type)
    {
        Verifier instance(public_key, hash_type);
        return instance.verify_data(data, signature);
    }
    [[deprecated]]
    [[nodiscard]] bool verify_hash(const KeyView public_key, const Hash hash, const ByteView signature)
    {
        Verifier instance(public_key, hash.hash_type);
        return instance.verify_hash(hash, signature);
    }

}