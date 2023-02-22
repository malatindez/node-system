#include <iostream>
#include <boost/asio.hpp>
#include <boost/array.hpp>

class udp_receiver {
public:
    udp_receiver(int port) : socket(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port)) {
        start_receive();
    }

    void start_receive() {
        socket.async_receive_from(boost::asio::buffer(recv_buffer), remote_endpoint,
            [this](boost::system::error_code ec, std::size_t bytes_recvd) {
                if (!ec && bytes_recvd > 0) {
                    std::cout << "Received " << bytes_recvd << " bytes: " << std::string(recv_buffer.data(), bytes_recvd) << std::endl;
                }
        start_receive();
            });
    }

    boost::asio::io_service io_service;
    boost::asio::ip::udp::socket socket;
    boost::array<char, 1024> recv_buffer;
    boost::asio::ip::udp::endpoint remote_endpoint;
};

int main() {
    udp_receiver receiver(1234);
    receiver.start_receive();
    receiver.io_service.run();

    return 0;
}