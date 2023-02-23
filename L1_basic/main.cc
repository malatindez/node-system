#include <iostream>
#include <boost/asio.hpp>
#include <openssl/aes.h>
#include <iostream>
class udp_client {
public:
    udp_client(const std::string& host, int port) : socket(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0)), endpoint(boost::asio::ip::address::from_string(host), port) {}

    void send(const std::string& message) {
        socket.async_send_to(boost::asio::buffer(message), endpoint,
            [this, &message](boost::system::error_code ec, std::size_t bytes_sent) {
                if (!ec && bytes_sent > 0) {
                    std::cout << "Sent " << bytes_sent << " bytes: " << message << std::endl;
                }
            });
    }

    boost::asio::io_service io_service;
    boost::asio::ip::udp::socket socket;
    boost::asio::ip::udp::endpoint endpoint;
};

int main() {
    udp_client client("127.0.0.1", 1234);
    std::string message;
    std::cout << "Write your secret message: ";
    std::cin >> message;
    client.send(message);

    client.io_service.run();

    return 0;
}