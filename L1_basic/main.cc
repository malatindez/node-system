#include <iostream>
#include <boost/asio.hpp>
#include "core/common/session.hpp"
#include <thread>
void ProcessIO(const bool& alive, std::unique_ptr<node_system::Session>& session)
{
    while (alive) {
        std::string message = "test message from client";

        if (message == "exit") {
            session.reset();
            break;
        }
        node_system::MessagePacket msg_packet;
        msg_packet.message = message + "\n";
        session->send_packet(msg_packet);
        std::cout << "Sent message: " << message << std::endl;

        while (session->has_packets())
        {
            auto packet = session->pop_packet_now();
            packet->type == utils::as_integer(node_system::NetworkPacketType::MESSAGE)
                ? std::cout << "Received message: " << reinterpret_cast<node_system::MessagePacket*>(packet.get())->message
                : std::cout << "Received unknown packet type: " << packet->type;
        }

        std::this_thread::yield();
    }
}
int main() {
    try {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::socket socket(io_context);
        socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1234));
        std::cout << "Connected to server." << std::endl;
        std::unique_ptr<node_system::Session> session = std::make_unique<node_system::Session>(io_context, std::move(socket));
        node_system::ByteArray key;
        node_system::ByteArray salt;
        key.resize(32);
        salt.resize(8);
        memcpy(key.data(), "12345678901234567890123456789012", 32);
        memcpy(salt.data(), "12345678", 8);
        int nrounds = 5;
        session->setup_encryption(key, salt, nrounds);

        bool alive = true;
        std::jthread console_io_thread{ ProcessIO, std::ref(alive), std::ref(session) };
        io_context.run();
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}