#include <boost/asio.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>
#include <filesystem>
#include "core/utils/utils.hpp"
#include "core/crypto/ecdsa.hpp"


namespace po = boost::program_options;

void WriteMergedKeys(std::string const& private_key_merged_file, std::string const& public_key_merged_file, bool force, std::vector<node_system::crypto::KeyPair> const& key_pairs)
{
    const auto private_path = std::filesystem::path(private_key_merged_file);
    const auto public_path = std::filesystem::path(public_key_merged_file);
    if (force)
    {
        if (std::filesystem::exists(private_path))
        {
            throw std::runtime_error("Private key file already exists");
        }
        if(std::filesystem::exists(public_path))
        {
            throw std::runtime_error("Public key file already exists");
        }
    }
    std::ofstream private_key_file(private_path);
    std::ofstream public_key_file(public_path);
    for(auto const& pair : key_pairs)
    {
        private_key_file.write(pair.private_key.as<char>(), pair.private_key.size());
        public_key_file.write(pair.public_key.as<char>(), pair.public_key.size());
        private_key_file << std::endl;
        public_key_file << std::endl;
    }
    private_key_file.close();
    public_key_file.close();
}

void WriteSeparateKeys(std::string const& private_key_output_folder, std::string const& public_key_output_folder, bool force, std::vector<node_system::crypto::KeyPair> const& key_pairs)
{
    int i = 0;
    for (auto const& pair : key_pairs)
    {
        i++;
        const auto private_path = std::filesystem::path(private_key_output_folder) / ("private" + std::to_string(i) + ".pem");
        const auto public_path = std::filesystem::path(public_key_output_folder) / ("public" + std::to_string(i) + ".pem");
        if (force)
        {
            if (std::filesystem::exists(private_path))
            {
                throw std::runtime_error("Private key file already exists");
            }
            if (std::filesystem::exists(public_path))
            {
                throw std::runtime_error("Public key file already exists");
            }
        }
        std::filesystem::create_directories(private_key_output_folder);
        std::filesystem::create_directories(public_key_output_folder);
        std::ofstream private_key_file(private_path);
        std::ofstream public_key_file(public_path);
        private_key_file.write(pair.private_key.as<char>(), pair.private_key.size());
        public_key_file.write(pair.public_key.as<char>(), pair.public_key.size());
        private_key_file.close();
        public_key_file.close();
    }
}

int main(int argc, char **argv)
{
    try
    {
        std::string private_key_output_folder = "private";
        std::string public_key_output_folder = "public";
        std::string curve = "secp256k1";
        uint32_t amount = 1;
        bool force = true;
        bool merge = false;
        std::string public_key_merged_file;
        std::string private_key_merged_file;


        po::options_description desc("Allowed options");
        desc.add_options()
            // First parameter describes option name/short name
            // The second is parameter to option
            // The third is description
            ("help,h", "print usage message")
            ("private-key-output-folder", po::value<std::string>(&private_key_output_folder), "pathname where to store generated private key")
            ("public-key-output-folder", po::value<std::string>(&public_key_output_folder), "pathname where to store generated public key")
            ("curve", po::value<std::string>(&curve), "curve name for ECDSA. Available: secp256k1, secp384r1, secp521r1")
            ("amount", po::value<uint32_t>(&amount), "Amount of keys to generate")
            ("force", po::value<bool>(&force), "force overwrite of existing files if they exist (default: true)")
            ("merge", po::value<bool>(&merge), "merge all generated keys into one file")
            ("public-key-merged-file", po::value<std::string>(&public_key_merged_file), "Output file for merged public keys")
            ("private-key-merged-file", po::value<std::string>(&private_key_merged_file), "Output file for merged private keys")
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
            private_key_output_folder = vm["private-key-output"].as<std::string>();
        }
        if (vm.contains("public-key-output"))
        {
            public_key_output_folder = vm["public-key-output"].as<std::string>();
        }
        if (vm.contains("curve"))
        {
            curve = vm["curve"].as<std::string>();
        }
        if (vm.contains("force"))
        {
            force = vm["force"].as<bool>();
        }
        if (vm.contains("merge"))
        {
            merge = vm["merge"].as<bool>();
        }
        if (vm.contains("public-key-merged-file"))
        {
            public_key_merged_file = vm["public-key-merged-file"].as<std::string>();
        }
        if (vm.contains("private-key-merged-file"))
        {
            private_key_merged_file = vm["private-key-merged-file"].as<std::string>();
        }

        using namespace node_system::crypto;
        using namespace node_system;
        std::vector<KeyPair> key_pairs;
        {
            ECDSA::KeyPairGenerator generator(curve);

            for (int i = 0; i < amount; i++)
            {
                KeyPair pair = generator.generate();
                ECDSA::Signer signer{ pair.private_key, Hash::HashType::SHA256 };
                ECDSA::Verifier verifier{ pair.public_key, Hash::HashType::SHA256 };

                ByteArray random_bytes;
                {
                    random_bytes.resize(4096);
                    std::ranges::generate(random_bytes, []() -> std::byte {return static_cast<std::byte>(std::rand() % 0xFF); });
                }

                Hash hash = SHA::ComputeHash(random_bytes, Hash::HashType::SHA256);

                ByteArray signature = signer.sign_hash(hash);
                bool result = verifier.verify_hash(hash, signature);

                /* Example
                ByteArray signature = signer.sign_data(pair.private_key, random_bytes, Hash::HashType::SHA256);
                bool result = verifier.verify_data(pair.public_key, random_bytes, signature, Hash::HashType::SHA256);
                */

                utils::AlwaysAssert(result, "Error: keypair verification has failed.");
                key_pairs.push_back(pair);
            }
        }
        if(merge)
        {
            WriteMergedKeys(private_key_merged_file, public_key_merged_file, force, key_pairs);
        }
        else
        {
            WriteSeparateKeys(private_key_output_folder, public_key_output_folder, force, key_pairs);
        }
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << "\n";
    }
}