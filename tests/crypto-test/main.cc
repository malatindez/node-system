#define DEBUG_UTILS_ASSERT_LOGS 0
#define DEBUG_UTILS_ASSERT_ABORTS 0
#define DEBUG_UTILS_ASSERT_THROWS 1
#define DEBUG_UTILS_ASSERT_ENABLED 1
#define DEBUG_UTILS_ALWAYS_ASSERT_ENABLED 1
#define DEBUG_UTILS_FORCE_ASSERT 0

#include "core/utils/utils.hpp"

#include "pch.h"
#include "core/crypto/aes.hpp"
#include "core/crypto/diffie-hellman.hpp"
#include "core/crypto/ecdsa.hpp"
#include "core/crypto/sha.hpp"
#include "utils.hpp"
#include "boost/endian/conversion.hpp"

using namespace node_system;
using namespace node_system::crypto;
ByteArray random_bytes(uint32_t amount)
{
    using random_bytes_engine = std::independent_bits_engine<std::default_random_engine, CHAR_BIT, unsigned short>;
    static random_bytes_engine rbe;

    ByteArray random_bytes(amount);
    std::generate(std::begin(random_bytes), std::end(random_bytes), []() { return static_cast<std::byte>(rbe()); });
    return random_bytes;
}

void TestECDSA_KEYGEN_THROWS_HELPER(std::string_view curve_name)
{
    ECDSA::KeyPairGenerator key_pair_generator(curve_name);
    ByteArray bytes = random_bytes(4096);
    auto test = [&](Hash::HashType first_hash_type, Hash::HashType second_hash_type, Hash::HashType third_hash_type) {
        for (int i = 0; i < 3; i++)
        {
            auto key_pair = key_pair_generator.generate();
            ECDSA::Signer signer{ key_pair.private_key, first_hash_type };
            ECDSA::Verifier verifier{ key_pair.public_key, second_hash_type };

            Hash hash = SHA::ComputeHash(bytes, third_hash_type);
            EXPECT_ANY_THROW({
                    ByteArray signature = signer.sign_hash(hash);
                    bool result = verifier.verify_hash(hash, signature);
                    EXPECT_TRUE(result);
                });
        }
    };
    test(Hash::HashType::SHA256, Hash::HashType::SHA384, Hash::HashType::SHA256);
    test(Hash::HashType::SHA256, Hash::HashType::SHA512, Hash::HashType::SHA256);
    test(Hash::HashType::SHA384, Hash::HashType::SHA256, Hash::HashType::SHA384);
    test(Hash::HashType::SHA384, Hash::HashType::SHA512, Hash::HashType::SHA384);
    test(Hash::HashType::SHA512, Hash::HashType::SHA256, Hash::HashType::SHA512);
    test(Hash::HashType::SHA512, Hash::HashType::SHA384, Hash::HashType::SHA512);
}

TEST(TEST_CRYPTO, TestECDSA_KEYGEN_THROWS)
{
    spdlog::set_level(spdlog::level::off);
    EXPECT_THROW(ECDSA::GetCurveByName("abcdefg"), std::runtime_error);

    EXPECT_NO_THROW(ECDSA::GetCurveByName("secp256k1"));
    EXPECT_NO_THROW(ECDSA::GetCurveByName("secp384r1"));
    EXPECT_NO_THROW(ECDSA::GetCurveByName("secp521r1"));

    TestECDSA_KEYGEN_THROWS_HELPER("secp256k1");
    TestECDSA_KEYGEN_THROWS_HELPER("secp384r1");
    TestECDSA_KEYGEN_THROWS_HELPER("secp521r1");
}

void TestECDSA_KEYGEN(Hash::HashType hash_type, std::string_view curve_name)
{
    ECDSA::KeyPairGenerator key_pair_generator(curve_name);
    ByteArray bytes = random_bytes(4096);
    for (int i = 0; i < 32; i++)
    {
        auto key_pair = key_pair_generator.generate();
        ECDSA::Signer signer{ key_pair.private_key, hash_type };
        ECDSA::Verifier verifier{ key_pair.public_key, hash_type };

        ByteArray signature = signer.sign_data(bytes);
        bool result = verifier.verify_data(bytes, signature);
        ASSERT_TRUE(result);
    }
    bytes = random_bytes(4096);
    for (int i = 0; i < 32; i++)
    {
        auto key_pair = key_pair_generator.generate();
        ECDSA::Signer signer{ key_pair.private_key, hash_type };
        ECDSA::Verifier verifier{ key_pair.public_key, hash_type };

        Hash hash = SHA::ComputeHash(bytes, hash_type);

        ByteArray signature = signer.sign_hash(hash);
        bool result = verifier.verify_hash(hash, signature);
        ASSERT_TRUE(result);
    }
}

TEST(TEST_CRYPTO, TestECDSA_KEYGEN_SHA256)
{
    TestECDSA_KEYGEN(Hash::HashType::SHA256, "secp256k1");
    TestECDSA_KEYGEN(Hash::HashType::SHA256, "secp384r1");
    TestECDSA_KEYGEN(Hash::HashType::SHA256, "secp521r1");
}

TEST(TEST_CRYPTO, TestECDSA_KEYGEN_SHA384)
{
    TestECDSA_KEYGEN(Hash::HashType::SHA384, "secp256k1");
    TestECDSA_KEYGEN(Hash::HashType::SHA384, "secp384r1");
    TestECDSA_KEYGEN(Hash::HashType::SHA384, "secp521r1");
}

TEST(TEST_CRYPTO, TestECDSA_KEYGEN_SHA512)
{
    TestECDSA_KEYGEN(Hash::HashType::SHA512, "secp256k1");
    TestECDSA_KEYGEN(Hash::HashType::SHA512, "secp384r1");
    TestECDSA_KEYGEN(Hash::HashType::SHA512, "secp521r1");
}

void TEST_HASH_Test(Hash::HashType hash_type, uint32_t expected_hash_size)
{
    for (int i = 0; i < 4096; i++)
    {
        ByteArray bytes = random_bytes(128);
        Hash hash = SHA::ComputeHash(bytes, hash_type);
        ASSERT_EQ(hash.size(), expected_hash_size);

        ByteArray bytes2 = random_bytes(512);
        Hash hash2 = SHA::ComputeHash(bytes2, hash_type);
        ASSERT_EQ(hash2.size(), expected_hash_size);

        Hash hash3 = SHA::ComputeHash(bytes, hash_type);
        ASSERT_EQ(hash3.size(), expected_hash_size);
        ASSERT_EQ(memcmp(hash.data(), hash3.data(), expected_hash_size), 0);
        Hash hash4 = SHA::ComputeHash(bytes2, hash_type);
        ASSERT_EQ(hash2.size(), expected_hash_size);
        ASSERT_EQ(memcmp(hash2.data(), hash4.data(), expected_hash_size), 0);
    }
}

TEST(TEST_CRYPTO, TestHASH_TestSHA256)
{
    TEST_HASH_Test(Hash::HashType::SHA256, 32);
}

TEST(TEST_CRYPTO, TestHASH_TestSHA384)
{
    TEST_HASH_Test(Hash::HashType::SHA384, 48);
}

TEST(TEST_CRYPTO, TestHASH_TestSHA512)
{
    TEST_HASH_Test(Hash::HashType::SHA512, 64);
}

TEST(TEST_CRYPTO, TEST_AES)
{
    for (int i = 0; i < 4096; i++) {
        ByteArray bytes = random_bytes(utils::Random<uint32_t>(1, 16384));
        ByteArray key = random_bytes(32);
        ByteArray salt = random_bytes(8);
        AES::AES256 aes{ key, salt, utils::Random<int>(1, 20) };
        ByteArray encrypted = aes.encrypt(bytes);
        ByteArray decrypted = aes.decrypt(encrypted);

        ASSERT_EQ(bytes.size(), decrypted.size());
        ASSERT_TRUE(memcmp(bytes.data(), decrypted.data(), bytes.size()) == 0);
    }
}

TEST(TEST_CRYPTO, TEST_DH)
{
    for (int i = 0; i < 32; i++)
    {
        DiffieHellmanHelper helper1;
        ByteArray h1_pubkey = helper1.get_public_key();

        for (int j = 0; j < 32; j++)
        {
            DiffieHellmanHelper helper2;
            ByteArray h2_pubkey = helper2.get_public_key();

            ByteArray key1 = helper1.get_shared_secret(h2_pubkey);
            ByteArray key2 = helper2.get_shared_secret(h1_pubkey);

            ASSERT_EQ(key1.size(), key2.size());

            ASSERT_TRUE(memcmp(key1.data(), key2.data(), key1.size()) == 0);
            key1 = SHA::ComputeHash(key1, Hash::HashType::SHA256).hash_value;
            key2 = SHA::ComputeHash(key2, Hash::HashType::SHA256).hash_value;
            ASSERT_TRUE(memcmp(key1.data(), key2.data(), key1.size()) == 0);
        }
    }
}

TEST(TEST_CRYPTO, FULL_TEST)
{
    ECDSA::KeyPairGenerator key_pair_generator("secp256k1");
    KeyPair keypair = key_pair_generator.generate();

    Key public_key = keypair.public_key;
    Key private_key = keypair.private_key;

    ECDSA::Signer server_sign{ keypair.private_key, Hash::HashType::SHA256 };
    ECDSA::Verifier client_verify{ keypair.public_key, Hash::HashType::SHA256 };

    DiffieHellmanHelper server_DH;
    DiffieHellmanHelper client_DH;

    ByteArray server_packet;
    ByteArray client_packet;

    { // client
        // Make request to the server, request public DH key
        uint32_t client_packet_size = 0;
        uint32_t client_packet_type = /* DH key exchange */ 0;
        ByteArray public_key = client_DH.get_public_key();
        client_packet_size =
            4 +                // packet size
            4 +                // packet type
            public_key.size(); // public key
        ByteArray packet_size = ByteArray::from_integral(boost::endian::native_to_little(client_packet_size));
        ByteArray packet_type = ByteArray::from_integral(boost::endian::native_to_little(client_packet_type));
        client_packet = ByteArray::from_byte_arrays(packet_size, packet_type, public_key);
    }
    ByteArray server_shared_secret;
    ByteArray server_shared_key;

    std::unique_ptr<AES::AES256> server_aes = nullptr;
    { // server
        // Receive client packet, send server public DH key
        ByteView client_packet_size = client_packet.view(0, 4);
        ByteView client_packet_type = client_packet.view(4, 4);
        ByteView client_public_key = client_packet.view(8, client_packet.size() - 8);
        uint32_t client_packet_size_val = boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(client_packet_size.data()));
        uint32_t client_packet_type_val = boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(client_packet_type.data()));
        ASSERT_EQ(client_packet_size_val, client_packet.size());
        ASSERT_EQ(client_packet_type_val, 0);
        ASSERT_EQ(client_public_key.size(), client_DH.get_public_key().size());
        ASSERT_EQ(memcmp(client_public_key.data(), client_DH.get_public_key().data(), client_public_key.size()), 0);

        uint32_t server_packet_size = 0;
        uint32_t server_packet_type = /* DH key exchange reply */ 1;
        ByteArray public_key = server_DH.get_public_key();

        ByteArray packet_type = ByteArray::from_integral(boost::endian::native_to_little(server_packet_type));

        ByteArray data = public_key;

        ByteArray signature = server_sign.sign_data(data);

        server_packet_size =
            4 +                // packet size
            4 +                // packet type
            4 +                // data size
            8 +                // salt
            //            2 +                // nrounds, disabled for simplicity
            data.size() +      // data
            signature.size()   // signature, size: packet size - 12 - data size
            ;
        ByteArray packet_size = ByteArray::from_integral(boost::endian::native_to_little(uint32_t(server_packet_size)));
        ByteArray data_size = ByteArray::from_integral(boost::endian::native_to_little(uint32_t(data.size())));
        ByteArray salt = random_bytes(8);
        server_packet = ByteArray::from_byte_arrays
        (
            packet_size,
            packet_type,
            data_size,
            salt, // salt
            data,
            signature
        );
        server_shared_secret = server_DH.get_shared_secret(client_public_key);
        server_shared_key = SHA::ComputeHash(server_shared_secret, Hash::HashType::SHA256).hash_value;
        server_aes = std::make_unique<AES::AES256>(server_shared_key, salt);
    }
    ByteArray client_shared_secret;
    ByteArray client_shared_key;
    std::unique_ptr<AES::AES256> client_aes = nullptr;
    { // client
        // Receive server packet
        ByteView server_packet_size = server_packet.view(0, 4);
        ByteView server_packet_type = server_packet.view(4, 4);
        ByteView server_public_key_size = server_packet.view(8, 4);
        ByteView server_salt = server_packet.view(12, 8);
        ByteView server_public_key = server_packet.view(20, boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(server_public_key_size.data())));
        ByteView server_signature = server_packet.view(20 + server_public_key.size(), server_packet.size() - 20 - server_public_key.size());

        uint32_t server_packet_size_val = boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(server_packet_size.data()));
        uint32_t server_packet_type_val = boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(server_packet_type.data()));
        uint32_t server_public_key_size_val = boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(server_public_key_size.data()));

        ASSERT_EQ(server_packet_size_val, server_packet.size());
        ASSERT_EQ(server_packet_type_val, 1);
        ASSERT_EQ(server_public_key_size_val, server_public_key.size());

        ASSERT_TRUE(client_verify.verify_data(server_public_key, server_signature));

        client_shared_secret = client_DH.get_shared_secret(server_public_key);
        client_shared_key = SHA::ComputeHash(client_shared_secret, Hash::HashType::SHA256).hash_value;
        client_aes = std::make_unique<AES::AES256>(client_shared_key, server_salt);
    }
    ASSERT_EQ(client_shared_secret.size(), server_shared_secret.size());
    ASSERT_EQ(client_shared_key.size(), server_shared_key.size());
    ASSERT_EQ(memcmp(client_shared_secret.data(), server_shared_secret.data(), client_shared_secret.size()), 0);
    ASSERT_EQ(memcmp(client_shared_key.data(), server_shared_key.data(), client_shared_key.size()), 0);
    // Above is key preparation

    for (int i = 0; i < 4096; i++)
    {
        ByteArray random_data = random_bytes(4096);
        { // client
            uint32_t client_packet_size = 0;
            uint32_t client_packet_type = /* random data send */ 2;
            ByteArray packet_type = ByteArray::from_integral(boost::endian::native_to_little(client_packet_type));

            ByteArray data = ByteArray::from_byte_arrays(packet_type, random_data);
            data = client_aes->encrypt(data);

            client_packet_size =
                4 +                // packet size
                data.size(); // random data to decrypt
            ByteArray packet_size = ByteArray::from_integral(boost::endian::native_to_little(client_packet_size));
            client_packet = ByteArray::from_byte_arrays(packet_size, data);
        }

        { // server
            ByteView client_packet_size = client_packet.view(0, 4);
            ByteView client_data = client_packet.view(4, client_packet.size() - 4);

            uint32_t client_packet_size_val = boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(client_packet_size.data()));

            ASSERT_EQ(client_packet_size_val, client_packet.size());

            ByteArray decrypted_packet = server_aes->decrypt(client_data);
            ByteView decrypted_packet_type = decrypted_packet.view(0, 4);
            ByteView decrypted_data = decrypted_packet.view(4, decrypted_packet.size() - 4);
            uint32_t decrypted_packet_type_val = boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(decrypted_packet_type.data()));
            ASSERT_EQ(decrypted_packet_type_val, 2);
            ASSERT_EQ(decrypted_data.size(), random_data.size());
            ASSERT_EQ(memcmp(decrypted_data.data(), random_data.data(), decrypted_data.size()), 0);

            // send back
            uint32_t server_packet_size = 0;
            uint32_t server_packet_type = /* random data reply */ 3;
            ByteArray packet_type = ByteArray::from_integral(boost::endian::native_to_little(server_packet_type));

            ByteArray data = ByteArray::from_byte_arrays(packet_type, decrypted_data);
            data = server_aes->encrypt(data);

            server_packet_size =
                4 +                // packet size
                data.size(); // random data to decrypt
            ByteArray packet_size = ByteArray::from_integral(boost::endian::native_to_little(server_packet_size));
            server_packet = ByteArray::from_byte_arrays(packet_size, data);
        }

        { // client
            ByteView server_packet_size = server_packet.view(0, 4);
            ByteView server_data = server_packet.view(4, server_packet.size() - 4);

            uint32_t server_packet_size_val = boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(server_packet_size.data()));

            ASSERT_EQ(server_packet_size_val, server_packet.size());

            ByteArray decrypted_packet = client_aes->decrypt(server_data);
            ByteView decrypted_packet_type = decrypted_packet.view(0, 4);
            ByteView decrypted_data = decrypted_packet.view(4, decrypted_packet.size() - 4);
            uint32_t decrypted_packet_type_val = boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(decrypted_packet_type.data()));
            ASSERT_EQ(decrypted_packet_type_val, 3);
            ASSERT_EQ(decrypted_data.size(), random_data.size());
            ASSERT_EQ(memcmp(decrypted_data.data(), random_data.data(), decrypted_data.size()), 0);
        }
    }
}