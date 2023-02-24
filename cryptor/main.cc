#include <boost/asio.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>
#include <filesystem>
#include "core/utils/utils.hpp"
#include "core/crypto/aes.hpp"


namespace po = boost::program_options;

int main(int argc, char **argv)
{
    try
    {
        std::string input_file;
        std::string output_file;
        std::string key;
        std::string salt;
        bool encrypt = false;
        bool decrypt = false;


        po::options_description desc("Allowed options");
        desc.add_options()
            // First parameter describes option name/short name
            // The second is parameter to option
            // The third is description
            ("help,h", "print usage message")
            ("input-file", po::value<std::string>(&input_file), "pathname where to read encrypted/decrypted data")
            ("output-file", po::value<std::string>(&output_file), "pathname where to store encrypted/decrypted data")
            ("key", po::value<std::string>(&key), "key for encryption/decryption")
            ("salt", po::value<std::string>(&salt), "salt for key derivation")
            ("encrypt", po::bool_switch(&encrypt), "encrypt file")
            ("decrypt", po::bool_switch(&decrypt), "decrypt file")
        ;

        po::variables_map vm;
        store(parse_command_line(argc, argv, desc), vm);

        if (vm.contains("help"))
        {
            std::cout << desc << "\n";
            return 0;
        }

        if(vm.contains("input-file"))
        {
            input_file = vm["input-file"].as<std::string>();
        }
        if(vm.contains("output-file"))
        {
            output_file = vm["output-file"].as<std::string>();
        }
        if(vm.contains("key"))
        {
            key = vm["key"].as<std::string>();
        }
        if(vm.contains("salt"))
        {
            salt = vm["salt"].as<std::string>();
        }
        if(vm.contains("encrypt"))
        {
            encrypt = vm["encrypt"].as<bool>();
        }
        if(vm.contains("decrypt"))
        {
            decrypt = vm["decrypt"].as<bool>();
        }
        
        utils::Assert(!(encrypt && decrypt), "You can't encrypt and decrypt at the same time");
        utils::Assert(encrypt || decrypt, "You must specify either encrypt or decrypt");
        utils::Assert(!input_file.empty(), "You must specify input file");
        utils::Assert(!output_file.empty(), "You must specify output file");
        utils::Assert(!key.empty(), "You must specify key");
        utils::Assert(!salt.empty(), "You must specify salt");
        utils::Assert(std::filesystem::exists(input_file), "Input file doesn't exist");
        utils::Assert(!std::filesystem::exists(output_file), "Output file already exists");
        utils::Assert(key.size() == 32, "Key must be 32 bytes long");
        utils::Assert(salt.size() == 8, "Salt must be 8 bytes long");
        using namespace node_system;
        using namespace node_system::crypto;
        using namespace node_system::crypto::AES;
        Key key_bytes;
        ByteArray salt_bytes;
        key_bytes.resize(32);
        salt_bytes.resize(8);
        std::copy_n(key.begin(), 32, key_bytes.as<char>());
        std::copy_n(salt.begin(), 8, salt_bytes.as<char>());

        std::ifstream input(input_file, std::ios::binary);
        ByteArray input_bytes;
        input.seekg(0, std::ios::end);
        input_bytes.resize(input.tellg());
        input.seekg(0, std::ios::beg);
        input.read((char*)input_bytes.data(), input_bytes.size());
        input.close();
        
        ByteArray output_bytes;
        node_system::crypto::AES::AES256 aes(key_bytes, salt_bytes);

        if(encrypt)
        {
            std::cout << "Encrypting file " << input_file << " to " << output_file << "\n";
            output_bytes = aes.encrypt(input_bytes);
            ByteArray test = aes.decrypt(output_bytes);
            for(int i = 0; i < test.size(); i++)
            {
                if(test[i] != input_bytes[i])
                {
                    std::cout << "Error at " << i << "\n";
                }
            }
        }
        else
        {
            std::cout << "Decrypting file " << input_file << " to " << output_file << "\n";
            output_bytes = aes.decrypt(input_bytes);
            ByteArray test = aes.encrypt(output_bytes);
            for(int i = 0; i < test.size(); i++)
            {
                if(test[i] != input_bytes[i])
                {
                    std::cout << "Error at " << i << "\n";
                }
            }
        }
        std::ofstream output(output_file, std::ios::binary);
        output.write((char*)output_bytes.data(), output_bytes.size());
        output.close();

        return 0;
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << "\n";
    }
}