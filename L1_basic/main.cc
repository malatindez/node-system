#include <iostream>
#include <boost/asio.hpp>
#include "core/common/session.hpp"
#include <thread>

#include "core/crypto/diffie-hellman.hpp"
#include "core/crypto/ecdsa.hpp"

std::string bytes_to_hex_str(node_system::ByteView const byte_view)
{
    std::string rv;
    for (int i = 0; i < byte_view.size(); i++)
    {
        const uint8_t val = static_cast<uint8_t>(byte_view[i]);
        const static std::string hex_values = "0123456789abcdef";
        rv += hex_values[val >> 4];
        rv += hex_values[val & 0xF];
    }
    return rv;
}

boost::asio::awaitable<void> process_packets(std::shared_ptr<node_system::Session> connection, boost::asio::io_context& io)
{
    while (true)
    {
        if (connection->is_closed())
            co_return;
        std::unique_ptr<node_system::Packet> packet = co_await connection->pop_packet_async(io);

        if (packet)
        {
            if (packet->type == utils::as_integer(node_system::NetworkPacketType::MESSAGE))
            {
                node_system::MessagePacket& msg = *reinterpret_cast<node_system::MessagePacket*>(packet.get());
                std::cout << "Received message: " << msg.message << std::endl;
                msg.message = std::to_string(std::stoi(msg.message) + 1);
                connection->send_packet(msg);
            }
            else
            {
                std::cout << "Received unknown packet type: " << packet->type;
            }
        }
    }
}

boost::asio::awaitable<void> setup_encryption_for_session(std::shared_ptr<node_system::Session> connection, boost::asio::io_context& io,
    node_system::crypto::ECDSA::Verifier& verifier)
{
    node_system::crypto::DiffieHellmanHelper dh{};
    node_system::DHKeyExchangePacket dh_packet;
    dh_packet.public_key = dh.get_public_key();
    connection->send_packet(dh_packet);

    while (true)
    {
        std::unique_ptr<node_system::Packet> packet = co_await connection->pop_packet_async(io);
        if (!packet)
        {
            co_return;
        }
        if (packet->type != utils::as_integer(node_system::CryptoPacketType::DH_KEY_EXCHANGE_RESPONSE))
        {
            spdlog::warn("Expected encryption request packet, received: {}", packet->type);
            continue;
        }
        spdlog::info("Received encryption response packet");

        node_system::DHKeyExchangeResponsePacket& response_packet = *reinterpret_cast<node_system::DHKeyExchangeResponsePacket*>(packet.get());
        if (!verifier.verify_hash(response_packet.get_hash(), response_packet.signature))
        {
            spdlog::warn("encryption response packet has the wrong signature. Aborting application.");
            std::abort();
        }

        node_system::ByteArray shared_secret = dh.get_shared_secret(response_packet.public_key);
        std::cout << "Computed shared secret: " << bytes_to_hex_str(shared_secret) << std::endl;
        shared_secret.append(response_packet.salt);
        const node_system::crypto::Hash shared_key = node_system::crypto::SHA::ComputeHash(shared_secret, node_system::crypto::Hash::HashType::SHA256);
        std::cout << "Computed shared key: " << bytes_to_hex_str(shared_key.hash_value) << std::endl;

        connection->setup_encryption(shared_key.hash_value, response_packet.salt, static_cast<uint16_t>(response_packet.n_rounds));
        break;
    }

    co_await process_packets(connection, io);
}

int main() {
    try {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::socket socket(io_context);
        socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1234));
        std::cout << "Connected to server." << std::endl;
        std::shared_ptr session = std::make_unique<node_system::Session>(io_context, std::move(socket));

        node_system::ByteArray public_key;
        std::ifstream public_key_file("core_public.pem");
        // count amount of bytes in file
        public_key_file.seekg(0, std::ios::end);
        public_key.resize(public_key_file.tellg());
        public_key_file.seekg(0, std::ios::beg);
        public_key_file.read(reinterpret_cast<char*>(public_key.data()), public_key.size());
        public_key_file.close();

        node_system::crypto::ECDSA::Verifier verifier{ public_key, node_system::crypto::Hash::HashType::SHA256 };
        co_spawn(socket.get_executor(), std::bind(&setup_encryption_for_session, session, std::ref(io_context), std::ref(verifier)), boost::asio::detached);

        io_context.run();
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}