#include <iostream>
#include <boost/asio.hpp>
#include "core/common/session.hpp"
int main() {
    try {
        boost::asio::io_service io_service;
        boost::asio::ip::tcp::socket socket(io_service);

        socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1234));
        std::cout << "Connected to server." << std::endl;

        while (true) {
            std::string message;
            std::getline(std::cin, message);

            if (message == "exit") {
                break;
            }

            boost::asio::write(socket, boost::asio::buffer(message + "\n"));
            std::cout << "Sent message: " << message << std::endl;
        }
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}