#pragma once
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/asio/spawn.hpp>
#include <memory>
#include <queue>

#include "packet.hpp"
#include "../crypto/aes.hpp"
#include "../utils/utils.hpp"
#include "../../include/spdlog.hpp"

namespace node_system
{
    class Session : public utils::non_copyable_non_movable, public std::enable_shared_from_this<Session>
    {
    public:
        explicit Session(boost::asio::io_context& io, boost::asio::ip::tcp::socket&& socket) : socket_(std::move(socket))
        {
            receive_all();
            // call async packet forger

            co_spawn(socket_.get_executor(), std::bind(&Session::async_packet_forger, this, std::ref(io)), boost::asio::detached);
            co_spawn(socket_.get_executor(), std::bind(&Session::send_all, this, std::ref(io)), boost::asio::detached);
            //            co_spawn(socket_.get_executor(), std::bind(&Session::read_all, this), boost::asio::detached);
            if (alive_ = socket_.is_open();
                alive_)
                spdlog::info("Session created");
        }
        virtual ~Session() = default;

        template<typename T>
        void send_packet(const T& packet_arg) requires std::is_base_of_v<Packet, T>
        {
            if (!alive_)
            {
                spdlog::warn("Session is closed, cannot send packet");
                return;
            }
            const auto& packet = static_cast<const Packet&>(packet_arg);
            ByteArray buffer = uint32_to_bytes(packet.type);
            packet.serialize(buffer);
            if (aes_)
            {
                buffer = encrypt(buffer);
            }
            std::unique_lock lock{ packets_to_send_mutex_ };
            packets_to_send_.push(std::move(buffer));
        }

        std::unique_ptr<Packet> pop_packet_now()
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
        /**
         * Returns nullptr if socket has crashed.
         * If not, it will wait until the packet is available and will return it as soon as possible.
         * This coroutine can be called in another context, cause it calls pop_packet_now which synchronizes using mutex.
         */
        boost::asio::awaitable<std::unique_ptr<Packet>> pop_packet_async(boost::asio::io_context& io)
        {
            std::weak_ptr<Session> weak_ptr_to_this = shared_from_this();
            
            boost::asio::steady_timer timer(io, std::chrono::milliseconds(1));
            while (true)
            {
                // Lock session just to check.
                std::shared_ptr<Session> session_ptr = weak_ptr_to_this.lock();
                if (session_ptr == nullptr || !this->alive_)
                {
                    co_return nullptr;
                }

                std::unique_ptr<Packet> packet = pop_packet_now();

                if (packet)
                {
                    co_return packet;
                }

                co_await timer.async_wait(boost::asio::use_awaitable);
            }
        }
        bool has_packets() const
        {
            return !received_packets_.empty();
        }

        void setup_encryption(ByteArray key, ByteArray salt, short n_rounds)
        {
            aes_ = std::make_unique<crypto::AES::AES256>(key, salt, n_rounds);
        }

        [[nodiscard]] bool secured() const noexcept { return aes_ != nullptr; }
        [[nodiscard]] bool is_closed() const noexcept { return !alive_ && !packet_forger_alive_ && !send_all_alive_; }

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
                        socket_.close();
                        alive_ = false;
                        std::unique_lock lock{ packets_to_send_mutex_ };
                        std::queue<ByteArray>().swap(packets_to_send_);
                    }
                    else
                    {
                        spdlog::trace("Received total of {} bytes", length);
                    }
                });
        }
        boost::asio::awaitable<void> send_all(boost::asio::io_context& io)
        {
            bool writing = false;
            ByteArray data_to_send;
            data_to_send.reserve(1024 * 128);
            while (alive_)
            {
                boost::asio::steady_timer timer(io, std::chrono::milliseconds(1));
                if (!packets_to_send_.empty() && !writing)
                {
                    writing = true;
                    {
                        std::unique_lock lock{ packets_to_send_mutex_ };
                        data_to_send.clear();
                        for (int i = 0; (i < 1000 || data_to_send.size() > 1024 * 128) && !packets_to_send_.empty(); i++)
                        {
                            ByteView packet = packets_to_send_.front();
                            data_to_send.append(uint32_to_bytes(static_cast<uint32_t>(packet.size())));
                            data_to_send.append(packet);
                            packets_to_send_.pop();
                        }
                    }

                    async_write(socket_, boost::asio::buffer(data_to_send.as<char>(), data_to_send.size()),
                        [&](const boost::system::error_code ec, [[maybe_unused]] std::size_t length)
                        {
                            writing = false;
                    data_to_send.clear();
                    if (ec) { spdlog::warn("Error sending message: {}", ec.message()); }
                        }
                    );
                }
                co_await timer.async_wait(boost::asio::use_awaitable);
            }
            packet_forger_alive_ = false;
        }
        boost::asio::awaitable<void> async_packet_forger(boost::asio::io_context& io)
        {
            while (alive_)
            {
                boost::asio::steady_timer timer(io, std::chrono::milliseconds(1));
                if (buffer_.size() >= 4)
                {
                    ByteArray packet_size_data;
                    read_bytes_to(packet_size_data, 4);
                    const int64_t packet_size = bytes_to_uint32(packet_size_data);
                    utils::AlwaysAssert(packet_size != 0 && packet_size < 1024 * 1024 * 8, "The amount of bytes to read is too big");

                    while (static_cast<int64_t>(buffer_.size()) < packet_size && alive_)
                    {
                        co_await timer.async_wait(boost::asio::use_awaitable);
                    }
                    if (static_cast<int64_t>(buffer_.size()) < packet_size) // alive_ is false, we won't get any data anymore
                    {
                        spdlog::warn("The packet size is bigger than the buffer size");
                        break;
                    }

                    ByteArray packet_data;
                    read_bytes_to(packet_data, packet_size);
                    std::unique_lock lock{ received_packets_mutex_ };
                    received_packets_.push(packet_data);
                    continue;
                }
                co_await timer.async_wait(boost::asio::use_awaitable);
            }
            send_all_alive_ = false;
        }

        void read_bytes_to(ByteArray& byte_array, const size_t amount)
        {
            const size_t current_size = byte_array.size();
            byte_array.resize(current_size + amount);
            buffer_.sgetn(byte_array.as<char>() + current_size * sizeof(char), amount);
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

        bool packet_forger_alive_ = true;
        bool send_all_alive_ = true;

        bool alive_ = true;
        boost::asio::streambuf buffer_;
        boost::asio::ip::tcp::tcp::socket socket_;

        std::unique_ptr<crypto::AES::AES256> aes_ = nullptr;
    };
}