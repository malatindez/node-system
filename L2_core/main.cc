#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "core/common/session.hpp"
#include "core/crypto/diffie-hellman.hpp"
#include "core/crypto/ecdsa.hpp"
using namespace node_system;
using namespace node_system::crypto;

std::string bytes_to_hex_str(ByteView const byte_view)
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
class TcpServer {
public:
    TcpServer(boost::asio::io_context& io_context, unsigned short port, std::unique_ptr<ECDSA::Signer> signer)
        : acceptor_(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
        io_context_(io_context),
        signer_(std::move(signer))
    {
        do_accept();
        connections_.reserve(100);
    }
    ~TcpServer()
    {
        alive = false;
    }
private:
    boost::asio::awaitable<void> setup_encryption_for_session(std::shared_ptr<node_system::Session> connection, boost::asio::io_context& io)
    {
        while (true)
        {
            std::unique_ptr<Packet> packet = co_await connection->pop_packet_async(io);

            if (packet->type != utils::as_integer(CryptoPacketType::DH_KEY_EXCHANGE))
            {
                spdlog::warn("Expected encryption request packet, received: {}", packet->type);
                continue;
            }
            spdlog::info("Received encryption request packet");

            DHKeyExchangePacket& dh_packet = *reinterpret_cast<DHKeyExchangePacket*>(packet.get());
            DiffieHellmanHelper dh{};
            DHKeyExchangeResponsePacket response_packet;
            response_packet.public_key = dh.get_public_key();

            std::mt19937_64 rng(std::random_device{}());

            response_packet.salt = ByteArray{ 8 };

            std::generate(response_packet.salt.begin(), response_packet.salt.end(),
                [&rng]() -> std::byte
                {
                    return static_cast<std::byte>(
                        static_cast<std::uint8_t>(std::uniform_int_distribution<uint16_t>(0, 255)(rng))
                        );
                });
            response_packet.n_rounds = 5 + static_cast<int>(std::chi_squared_distribution<float>(2)(rng));
            response_packet.n_rounds = std::min(response_packet.n_rounds, 5);
            response_packet.n_rounds = std::max(response_packet.n_rounds, 20);

            response_packet.signature = signer_->sign_hash(response_packet.get_hash());

            ByteArray shared_secret = dh.get_shared_secret(dh_packet.public_key);
            shared_secret.append(response_packet.salt);
            std::cout << "Computed shared secret: " << bytes_to_hex_str(shared_secret) << std::endl;
            const Hash shared_key = SHA::ComputeHash(shared_secret, Hash::HashType::SHA256);
            std::cout << "Computed shared key: " << bytes_to_hex_str(shared_key.hash_value) << std::endl;

            connection->send_packet(response_packet);
            connection->setup_encryption(shared_key.hash_value, response_packet.salt, static_cast<uint16_t>(response_packet.n_rounds));
            break;
        }
        std::unique_lock lock{ connection_access };
        connections_.push_back(connection);

        co_await process_packets(connection, io);
    }
    boost::asio::awaitable<void> process_packets(std::shared_ptr<node_system::Session> connection, boost::asio::io_context& io)
    {
        MessagePacket msg;
        msg.message = "0";
        connection->send_packet(msg);
        while (true)
        {
            std::unique_ptr<node_system::Packet> packet = co_await connection->pop_packet_async(io);

            if (packet)
            {
                if (packet->type == utils::as_integer(node_system::NetworkPacketType::MESSAGE))
                {
                    MessagePacket& msg = *reinterpret_cast<node_system::MessagePacket*>(packet.get());
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
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
                if (ec) {
                    std::cerr << "Error accepting connection: " << ec.message() << std::endl;
                }
                else {
                    std::cout << "New connection established." << std::endl;
                    const auto connection = std::make_shared<node_system::Session>(io_context_, std::move(socket));
                    co_spawn(socket.get_executor(), std::bind(&TcpServer::setup_encryption_for_session, this, connection, std::ref(io_context_)), boost::asio::detached);
                }
        do_accept();
            });
    }
    std::mutex connection_access;
    bool alive = true;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<node_system::Session>> connections_;
    boost::asio::io_context& io_context_;
    std::unique_ptr<crypto::ECDSA::Signer> signer_;
};

int main() {
    try {
        boost::asio::io_context io_context;
        ByteArray private_key;
        std::ifstream private_key_file("core_private.pem");
        // count amount of bytes in file
        private_key_file.seekg(0, std::ios::end);
        private_key.resize(private_key_file.tellg());
        private_key_file.seekg(0, std::ios::beg);
        private_key_file.read(reinterpret_cast<char*>(private_key.data()), private_key.size());
        private_key_file.close();

        std::unique_ptr<ECDSA::Signer> signer = std::make_unique<ECDSA::Signer>(private_key, Hash::HashType::SHA256);
        TcpServer server(io_context, 1234, std::move(signer));
        io_context.run();
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}