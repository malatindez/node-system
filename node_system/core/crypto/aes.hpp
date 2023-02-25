#pragma once
#include "common.hpp"
#include "../utils/utils.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>
namespace node_system::crypto::AES
{
    class AES256 : utils::non_copyable_movable
    {
    public:
        static constexpr uint32_t KEY_SIZE = 32;
        static constexpr uint32_t SALT_SIZE = 8;
        
        AES256(const KeyView input_key, const ByteView salt, const int nrounds = 5)
        {
            utils::AlwaysAssert(input_key.size() == 32, "Key size must be 32 bytes");
            utils::AlwaysAssert(salt.size() == 8, "Salt size must be 8 bytes");

            unsigned char key[32], iv[32];

            /*
            * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
            * nrounds is the number of times the we hash the material. More rounds are more secure but slower.
            */
            int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt.as<unsigned char>(), input_key.as<unsigned char>(), static_cast<int>(input_key.size()), nrounds, key, iv);

            utils::AlwaysAssert(i == 32, "Key size is " + std::to_string(i) + " bytes - should be 256 bits");

            encrypt_context_.reset(EVP_CIPHER_CTX_new());
            decrypt_context_.reset(EVP_CIPHER_CTX_new());
            EVP_CIPHER_CTX_init(encrypt_context_.get());
            EVP_EncryptInit_ex(encrypt_context_.get(), EVP_aes_256_cbc(), NULL, key, iv);
            EVP_CIPHER_CTX_init(decrypt_context_.get());
            EVP_DecryptInit_ex(decrypt_context_.get(), EVP_aes_256_cbc(), NULL, key, iv);
        }
        [[nodiscard]] ByteArray encrypt(const ByteView plaintext) const
        {
            /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
            utils::AlwaysAssert(plaintext.size() < INT_MAX - AES_BLOCK_SIZE, "Plaintext size is too large");
            int c_len = static_cast<int>(plaintext.size() + AES_BLOCK_SIZE);
            int f_len = 0;
            ByteArray ciphertext;
            ciphertext.resize(c_len);

            EVP_EncryptInit_ex(encrypt_context_.get(), NULL, NULL, NULL, NULL);
            EVP_EncryptUpdate(encrypt_context_.get(), ciphertext.as<unsigned char>(), &c_len, plaintext.as<unsigned char>(), static_cast<int>(plaintext.size()));
            EVP_EncryptFinal_ex(encrypt_context_.get(), ciphertext.as<unsigned char>() + c_len, &f_len);

            ciphertext.resize(c_len + f_len);
            return ciphertext;
        }
        [[nodiscard]] ByteArray decrypt(const ByteView ciphertext) const
        {
            /* plaintext will always be equal to or lesser than length of ciphertext*/
            int p_len = static_cast<int>(ciphertext.size());
            int f_len = 0;
            ByteArray plaintext;
            plaintext.resize(p_len);
            EVP_DecryptInit_ex(decrypt_context_.get(), NULL, NULL, NULL, NULL);
            EVP_DecryptUpdate(decrypt_context_.get(), plaintext.as<unsigned char>(), &p_len, ciphertext.as<unsigned char>(), static_cast<int>(ciphertext.size()));
            EVP_DecryptFinal_ex(decrypt_context_.get(), plaintext.as<unsigned char>() + p_len, &f_len);
            plaintext.resize(p_len + f_len);
            return plaintext;
        }
    private:
        EVP_CIPHER_CTX_WRAPPER encrypt_context_;
        EVP_CIPHER_CTX_WRAPPER decrypt_context_;
    };
}