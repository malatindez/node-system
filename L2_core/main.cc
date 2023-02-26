#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
public:
    TcpConnection(boost::asio::ip::tcp::socket socket) : socket_(std::move(socket)) {}

    void start() {
        doRead();
    }

    void send(const std::string& message) {
        auto self(shared_from_this());
        boost::asio::async_write(socket_, boost::asio::buffer(message + "\n"),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (ec)
                {
                    std::cerr << "Error sending message: " << ec.message() << std::endl;
                }
                else
                {
                    std::cout << "Successfully sent message of length " << length << std::endl;
                }
            });
    }

private:
    void doRead() {
        boost::asio::async_read(socket_, buffer_, boost::asio::transfer_all(),
            [this](boost::system::error_code ec, std::size_t length) {
                if (ec) {
                    std::cerr << "Error reading message: " << ec.message() << std::endl;
                }
                else {
                    std::istream is(&buffer_);
                    std::string message;
                    std::getline(is, message);
                    std::cout << "Received message: " << message << std::endl;
                    doRead();
                }
            });
    }

    boost::asio::ip::tcp::socket socket_;
    boost::asio::streambuf buffer_;
};

class TcpServer {
public:
    TcpServer(boost::asio::io_service& io_service, unsigned short port)
        : acceptor_(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
    {
        doAccept();
    }

private:
    void doAccept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
                if (ec) {
                    std::cerr << "Error accepting connection: " << ec.message() << std::endl;
                }
                else {
                    std::cout << "New connection established." << std::endl;
                    auto connection = std::make_shared<TcpConnection>(std::move(socket));
                    connections_.push_back(connection);
                    connection->start();
                }
        doAccept();
            });
    }

    boost::asio::ip::tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<TcpConnection>> connections_;
};

int main() {
    try {
        boost::asio::io_service io_service;
        TcpServer server(io_service, 1234);
        io_service.run();
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}