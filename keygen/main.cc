#include <boost/asio.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include "core/utils/utils.hpp"
#include <filesystem>


struct ByteView : public std::span<const std::byte>
{
    using std::span<const std::byte>::span;
    using std::span<const std::byte>::operator=;
    using std::span<const std::byte>::operator[];
    template<typename T>
    [[nodiscard]] const T* as() const
    {
        return reinterpret_cast<const T*>(data());
    }
};

struct ByteArray : public std::vector<std::byte>
{
    using std::vector<std::byte>::vector;
    using std::vector<std::byte>::operator=;
    using std::vector<std::byte>::operator[];
    template<typename T>
    [[nodiscard]] T* as()
    {
        return reinterpret_cast<T*>(data());
    }
    template<typename T>
    [[nodiscard]] const T* as() const
    {
        return reinterpret_cast<const T*>(data());
    }

    [[nodiscard]] ByteView as_view() const
    {
        return ByteView{ data(), size() };
    }
};
using Key = ByteArray;
using KeyView = ByteView;
struct KeyPair
{
    KeyPair(const Key private_key, const Key public_key) : private_key{ private_key }, public_key{public_key} {}

    [[nodiscard]] auto get_public_key_view() const { return KeyView{ public_key.data(), public_key.size() }; }
    [[nodiscard]] auto get_private_key_view() const { return KeyView{private_key.data(), private_key.size() }; }

    Key private_key;
    Key public_key;
};

int GetCurveType(std::string_view curve)
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

KeyPair GenerateKeyPair(std::string_view curve)
{
    // generate ecdsa key using openssl 3.0
    const int curve_name = GetCurveType(curve);
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY *pkey = nullptr;
    
    utils::AlwaysAssert(ctx != nullptr, "EVP_PKEY_CTX_new_id() failed");
    utils::AlwaysAssert(EVP_PKEY_keygen_init(ctx) > 0, "EVP_PKEY_keygen_init() failed");
    utils::AlwaysAssert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_name) > 0, "EVP_PKEY_CTX_set_ec_paramgen_curve_nid() failed");
    utils::AlwaysAssert(EVP_PKEY_keygen(ctx, &pkey) > 0, "EVP_PKEY_keygen() failed");
    unsigned char* key_data;
    unsigned long key_size;


    EVP_PKEY_CTX_free(ctx);
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
    BIO_get_mem_data(bio, &key_data);
    Key public_key;
    public_key.resize(key_size);
    std::copy_n(key_data, key_size, public_key.as<unsigned char>());
    BIO_free_all(bio);



    EVP_PKEY_free(pkey);
    return KeyPair{ private_key, public_key };
}

ByteArray Sign(const ByteView data, const KeyView private_key)
{
    BIO *bio = BIO_new_mem_buf(private_key.data(), static_cast<int>(private_key.size()));
    utils::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    utils::AlwaysAssert(pkey != nullptr, "PEM_read_bio_PrivateKey() failed");
    BIO_free(bio);

    BIO_new_mem_buf((void*)private_key.data(), static_cast<int>(private_key.size()));

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.as<const unsigned char>(), data.size(), hash);

    unsigned char* signature = nullptr;
    size_t signature_size = 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    utils::AlwaysAssert(ctx != nullptr, "EVP_PKEY_CTX_new() failed");
    utils::AlwaysAssert(EVP_PKEY_sign_init(ctx) > 0, "EVP_PKEY_sign_init() failed");
    utils::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0, "EVP_PKEY_CTX_set_signature_md() failed");
    utils::AlwaysAssert(EVP_PKEY_sign(ctx, nullptr, &signature_size, hash, sizeof(hash)) > 0, "EVP_PKEY_sign() failed");
    signature = static_cast<unsigned char *>(OPENSSL_malloc(signature_size));
    utils::AlwaysAssert(signature != nullptr, "OPENSSL_malloc() failed");
    utils::AlwaysAssert(EVP_PKEY_sign(ctx, signature, &signature_size, hash, sizeof(hash)) > 0, "EVP_PKEY_sign() failed");
    EVP_PKEY_CTX_free(ctx);

    ByteArray rv;
    rv.resize(signature_size);
    std::copy_n(reinterpret_cast<std::byte*>(signature), signature_size, rv.begin());
    OPENSSL_free(signature);
    EVP_PKEY_free(pkey);

    return rv;
}

bool Verify(const ByteArray data, const ByteArray signature, const KeyView public_key)
{
    BIO* bio = BIO_new_mem_buf(public_key.data(), static_cast<int>(public_key.size()));
    utils::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    utils::AlwaysAssert(pkey != nullptr, "PEM_read_bio_PUBKEY() failed");
    BIO_free(bio);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.as<unsigned char>(), data.size(), hash);
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    utils::AlwaysAssert(ctx != nullptr, "EVP_PKEY_CTX_new() failed");
    utils::AlwaysAssert(EVP_PKEY_verify_init(ctx) > 0, "EVP_PKEY_verify_init() failed");
    utils::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0, "EVP_PKEY_CTX_set_signature_md() failed");
    const bool return_value = EVP_PKEY_verify(ctx, signature.as<const unsigned char>(), signature.size(), hash, sizeof(hash)) > 0;
    EVP_PKEY_CTX_free(ctx);
  
    EVP_PKEY_free(pkey);
    return return_value;
}



namespace po = boost::program_options;

int main(int argc, char **argv)
{
    try
    {
        std::string private_key_output = "private.pem";
        std::string public_key_output = "public.pem";
        std::string curve = "secp256k1";
        bool force = true;

        po::options_description desc("Allowed options");
        desc.add_options()
            // First parameter describes option name/short name
            // The second is parameter to option
            // The third is description
            ("help,h", "print usage message")
            ("private-key-output", po::value<std::string>(&private_key_output), "pathname where to store generated private key")
            ("public-key-output", po::value<std::string>(&public_key_output), "pathname where to store generated public key")
            ("curve", po::value<std::string>(), "curve name for ECDSA. Available: secp256k1, secp384r1, secp521r1")
            ("force", po::value<bool>(), "force overwrite of existing files if they exist (default: true)")
        ;

        po::variables_map vm;
        store(parse_command_line(argc, argv, desc), vm);

        if (vm.contains("help"))
        {
            std::cout << desc << "\n";
            return 0;
        }

        if (vm.contains("private-key-output"))
        {
            private_key_output = vm["private-key-output"].as<std::string>();
        }
        if (vm.contains("public-key-output"))
        {
            public_key_output = vm["public-key-output"].as<std::string>();
        }
        if (vm.contains("curve"))
        {
            curve = vm["curve"].as<std::string>();
        }
        if (vm.contains("force"))
        {
            force = vm["force"].as<bool>();
        }

        std::cout << "output_private_key: " << private_key_output << "\n";
        std::cout << "output_public_key: " << public_key_output << "\n";
        std::cout << "curve: " << curve << "\n";
        std::cout << "force: " << force << "\n";
        utils::AlwaysAssert(!private_key_output.empty());
        utils::AlwaysAssert(!public_key_output.empty());

        if (!force)
        {
            if (std::filesystem::exists(private_key_output))
            {
                throw std::runtime_error("Private key file already exists");
            }
            if (std::filesystem::exists(public_key_output))
            {
                throw std::runtime_error("Public key file already exists");
            }
        }
        KeyPair pair = GenerateKeyPair(curve);
        ByteArray random_bytes;
        random_bytes.resize(4096);
        std::ranges::generate(random_bytes, []() -> std::byte {return static_cast<std::byte>(std::rand() % 0xFF); });
        ByteArray signature = Sign(random_bytes, pair.private_key);
        bool result = Verify(random_bytes, signature, pair.public_key);
        utils::AlwaysAssert(result, "Error, the keypair wasn't verified");
        std::ofstream private_key_file(private_key_output);
        std::ofstream public_key_file(public_key_output);
        private_key_file.write(pair.private_key.as<char>(), pair.private_key.size());
        public_key_file.write(pair.public_key.as<char>(), pair.public_key.size());
        private_key_file.close();
        public_key_file.close();
        
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << "\n";
    }
}