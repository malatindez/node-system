#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "core/common/session.hpp"

void ProcessIO(const bool& alive, std::vector<std::shared_ptr<node_system::Session>>& sessions_, std::mutex& connection_access)
{
    while (alive) {
        std::string message = "test message from server";

        if (message == "exit") {
            sessions_.clear();
            break;
        }
        node_system::MessagePacket msg_packet;
        msg_packet.message = message + "\n";
        if (std::ranges::any_of(sessions_, [](const auto& connection) { return connection->is_closed() && !connection->has_packets(); }))
        {
            std::unique_lock lock(connection_access);
            std::erase_if(sessions_, [](const auto& connection) { return connection->is_closed() && !connection->has_packets(); });
        }
        for (const auto& session : sessions_)
            if (!session->is_closed())
            {
                session->send_packet(msg_packet);
                std::cout << "Sent message: " << message << std::endl;
            }

        for (const auto& session : sessions_)
        {
            while (session->has_packets())
            {
                auto packet = session->pop_packet();
                if (packet)
                {
                    packet->type == utils::as_integer(node_system::NetworkPacketType::MESSAGE)
                        ? std::cout << "Received message: " << reinterpret_cast<node_system::MessagePacket*>(packet.get())->message
                        : std::cout << "Received unknown packet type: " << packet->type;
                }
            }
        }

        std::this_thread::yield();
    }
}

class TcpServer {
public:
    TcpServer(boost::asio::io_context& io_context, unsigned short port)
        : acceptor_(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
        io_context_(io_context)
    {
        do_accept();
        connections_.reserve(100);
    }
    ~TcpServer()
    {
        alive = false;
    }
private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
                if (ec) {
                    std::cerr << "Error accepting connection: " << ec.message() << std::endl;
                }
                else {
                    std::cout << "New connection established." << std::endl;
                    const auto connection = std::make_shared<node_system::Session>(io_context_, std::move(socket));
                    node_system::ByteArray key;
                    node_system::ByteArray salt;
                    key.resize(32);
                    salt.resize(8);
                    memcpy(key.data(), "12345678901234567890123456789012", 32);
                    memcpy(salt.data(), "12345678", 8);
                    int nrounds = 5;
                    connection->setup_encryption(key, salt, nrounds);
                    std::unique_lock lock{ connection_access };
                    connections_.push_back(connection);
                    //  connection->start();
                }
        do_accept();
            });
    }
    std::mutex connection_access;
    bool alive = true;
    std::jthread console_io_thread{ ProcessIO, std::ref(alive), std::ref(connections_), std::ref(connection_access) };
    boost::asio::ip::tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<node_system::Session>> connections_;
    boost::asio::io_context& io_context_;
};

int main() {
    try {
        boost::asio::io_context io_context;
        TcpServer server(io_context, 1234);
        io_context.run();
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}