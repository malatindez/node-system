#pragma once
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/endian/conversion.hpp>
#include <queue>

#include "packet.hpp"
#include "../crypto/aes.hpp"
#include "../utils/utils.hpp"
#include "../../include/spdlog.hpp"

namespace node_system
{
    class Session : public utils::non_copyable_non_movable
    {
    public:
        explicit Session(boost::asio::ip::tcp::socket socket) : socket_(std::move(socket))
        {
            receive_all();
            // call async packet forger
            co_spawn(socket_.get_executor(), std::bind(&Session::async_packet_forger, this), boost::asio::detached);
            co_spawn(socket_.get_executor(), std::bind(&Session::send_all, this), boost::asio::detached);
        }
        virtual ~Session() = default;

        void send_packet(const Packet& packet)
        {
            ByteArray buffer;
            packet.serialize(buffer);
            std::unique_lock lock{ packets_to_send_mutex_ };
            packets_to_send_.push(std::move(buffer));
        }

        std::unique_ptr<Packet> pop_packet()
        {
            if (const std::optional<ByteArray> packet_data = pop_packet_data();
                packet_data)
            {
                if (aes_)
                {
                    const ByteArray plain = decrypt(*packet_data);
                    const uint32_t packet_type = bytes_to_uint32(plain.view(0, 4));
                    return PacketFactory::deserialize(plain.view(4), packet_type);
                }
                const uint32_t packet_type = bytes_to_uint32(packet_data->view(0, 4));
                return PacketFactory::deserialize(packet_data->view(4), packet_type);
            }
            return nullptr;
        }

        void setup_encryption(ByteArray key, ByteArray salt, short nrounds)
        {
            aes_ = std::make_unique<crypto::AES::AES256>(key, salt, nrounds);
        }

        [[nodiscard]] bool secured() const noexcept { return aes_ != nullptr; }

    protected:
        std::optional<ByteArray> pop_packet_data() noexcept
        {
            if (received_packets_.empty())
            {
                return std::nullopt;
            }
            std::unique_lock lock{ received_packets_mutex_ };
            const ByteArray packet = std::move(received_packets_.front());
            received_packets_.pop();
            return packet;
        }

    private:
        void receive_all()
        {
            boost::asio::async_read(socket_, buffer_, boost::asio::transfer_all(),
                [this](const boost::system::error_code ec, [[maybe_unused]] std::size_t length)
                {
                    if (ec)
                    {
                        spdlog::warn("Error reading message: {}", ec.message());
                        alive_ = false;
                    }
                    else
                    {
                        spdlog::trace("Received total of {} bytes", length);
                    }
            alive_ = false;
                });
        }
        boost::asio::awaitable<void> send_all()
        {
            bool writing = false;
            while (alive_)
            {
                if (!packets_to_send_.empty() && !writing)
                {
                    writing = true;
                    std::unique_lock lock{ packets_to_send_mutex_ };
                    const ByteArray packet = std::move(packets_to_send_.front());
                    packets_to_send_.pop();

                    async_write(socket_, boost::asio::buffer(packet.as<char>(), packet.size()),
                        [&](const boost::system::error_code ec, [[maybe_unused]] std::size_t length)
                        {
                            writing = false;
                    if (ec) { spdlog::warn("Error sending message: {}", ec.message()); }
                        }
                    );
                }
                co_await boost::asio::this_coro::executor;
            }
        }
        boost::asio::awaitable<void> async_packet_forger()
        {
            while (alive_)
            {
                if (buffer_.size() >= 4)
                {
                    ByteArray packet_size_data;
                    read_bytes_to(packet_size_data, 4);
                    const int64_t packet_size = bytes_to_uint32(packet_size_data);
                    utils::AlwaysAssert(packet_size != 0 && packet_size < 1024 * 1024 * 8, "The amount of bytes to read is too big");
                    if (static_cast<int64_t>(buffer_.size()) >= packet_size - 4)
                    {
                        ByteArray packet_data;
                        read_bytes_to(packet_data, packet_size);
                        std::unique_lock lock{ received_packets_mutex_ };
                        received_packets_.push(packet_data);
                        continue;
                    }
                }
                co_await boost::asio::this_coro::executor;
            }
        }

        void read_bytes_to(ByteArray& byte_array, const size_t amount)
        {
            const size_t current_size = byte_array.size();
            byte_array.resize(current_size + amount);
            buffer_.sgetn(byte_array.as<char>() + current_size * sizeof(char), amount);
            buffer_.consume(amount);
        }

        static uint32_t bytes_to_uint32(const ByteView byte_view)
        {
            utils::Assert(byte_view.size() >= 4, "The byte array is too small to be converted to a uint32_t");
            return boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(byte_view.data()));
        }
        static ByteArray uint32_to_bytes(const uint32_t value)
        {
            ByteArray byte_array(4);
            *byte_array.as<uint32_t>() = boost::endian::native_to_little(value);
            return byte_array;
        }

        [[nodiscard]] ByteArray encrypt(const ByteArray& data) const
        {
            return aes_->encrypt(data);
        }

        [[nodiscard]] ByteArray decrypt(const ByteArray& data) const
        {
            return aes_->decrypt(data);
        }

        std::mutex received_packets_mutex_;
        std::queue<ByteArray> received_packets_;

        std::mutex packets_to_send_mutex_;
        std::queue<ByteArray> packets_to_send_;

        bool alive_ = true;
        boost::asio::streambuf buffer_;
        boost::asio::ip::tcp::tcp::socket socket_;

        std::unique_ptr<crypto::AES::AES256> aes_ = nullptr;
    };
}