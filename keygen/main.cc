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

void GenerateKeyPair(std::string_view output_private_key, std::string_view output_public_key, std::string_view curve, bool rewrite)
{
    if (!rewrite)
    {
        if (std::filesystem::exists(output_private_key))
        {
            throw std::runtime_error("Private key file already exists");
        }
        if (std::filesystem::exists(output_public_key))
        {
            throw std::runtime_error("Public key file already exists");
        }
    }

    // generate ecdsa key using openssl 3.0
    const int curve_name = GetCurveType(curve);
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;
    
    utils::AlwaysAssert(ctx != nullptr, "EVP_PKEY_CTX_new_id() failed");
    utils::AlwaysAssert(EVP_PKEY_keygen_init(ctx) > 0, "EVP_PKEY_keygen_init() failed");
    utils::AlwaysAssert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_name) > 0, "EVP_PKEY_CTX_set_ec_paramgen_curve_nid() failed");
    utils::AlwaysAssert(EVP_PKEY_keygen(ctx, &pkey) > 0, "EVP_PKEY_keygen() failed");
    
    EVP_PKEY_CTX_free(ctx);

    BIO *bio = BIO_new_file(output_private_key.data(), "w");
    utils::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
    utils::AlwaysAssert(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) > 0, "PEM_write_bio_PrivateKey() failed");
    BIO_free(bio);

    bio = BIO_new_file(output_public_key.data(), "w");
    utils::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
    utils::AlwaysAssert(PEM_write_bio_PUBKEY(bio, pkey) > 0, "PEM_write_bio_PUBKEY() failed");
    BIO_free(bio);

    EVP_PKEY_free(pkey);
}

std::string Sign(void *data, uint32_t size, std::string_view private_key)
{
    BIO *bio = BIO_new_file(private_key.data(), "r");
    utils::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    utils::AlwaysAssert(pkey != nullptr, "PEM_read_bio_PrivateKey() failed");
    BIO_free(bio);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, size);
    SHA256_Final(hash, &sha256);

    unsigned char* signature = NULL;
    size_t signature_size = 0;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    utils::AlwaysAssert(ctx != nullptr, "EVP_PKEY_CTX_new() failed");
    utils::AlwaysAssert(EVP_PKEY_sign_init(ctx) > 0, "EVP_PKEY_sign_init() failed");
    utils::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0, "EVP_PKEY_CTX_set_signature_md() failed");
    utils::AlwaysAssert(EVP_PKEY_sign(ctx, NULL, &signature_size, hash, sizeof(hash)) > 0, "EVP_PKEY_sign() failed");
    signature = (unsigned char*)OPENSSL_malloc(signature_size);
    utils::AlwaysAssert(signature != nullptr, "OPENSSL_malloc() failed");
    utils::AlwaysAssert(EVP_PKEY_sign(ctx, signature, &signature_size, hash, sizeof(hash)) > 0, "EVP_PKEY_sign() failed");
    EVP_PKEY_CTX_free(ctx);

    std::string signature_str = std::string((char*)signature, signature_size);
    OPENSSL_free(signature);
    EVP_PKEY_free(pkey);

    return signature_str;
}

void Verify(void *data, uint32_t size, std::string_view signature_str, std::string_view public_key)
{
    BIO *bio = BIO_new_file(public_key.data(), "r");
    utils::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    utils::AlwaysAssert(pkey != nullptr, "PEM_read_bio_PUBKEY() failed");
    BIO_free(bio);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, size);
    SHA256_Final(hash, &sha256);

    
    const unsigned char* signature = reinterpret_cast<const unsigned char *>(signature_str.data());
    size_t signature_size = signature_str.size();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    utils::AlwaysAssert(ctx != nullptr, "EVP_PKEY_CTX_new() failed");
    utils::AlwaysAssert(EVP_PKEY_verify_init(ctx) > 0, "EVP_PKEY_verify_init() failed");
    utils::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0, "EVP_PKEY_CTX_set_signature_md() failed");
    utils::AlwaysAssert(EVP_PKEY_verify(ctx, signature, signature_size, hash, sizeof(hash)) > 0, "EVP_PKEY_verify() failed");
    EVP_PKEY_CTX_free(ctx);
  
    EVP_PKEY_free(pkey);
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

        GenerateKeyPair(private_key_output, public_key_output, curve, force);
        std::string random_bytes = "";
        random_bytes.resize(4096);
        std::generate(random_bytes.begin(), random_bytes.end(), std::rand);
        std::string signature = Sign(reinterpret_cast<void*>(random_bytes.data()), random_bytes.size(), private_key_output);
        Verify(reinterpret_cast<void*>(random_bytes.data()), random_bytes.size(), signature, public_key_output);
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << "\n";
    }
}