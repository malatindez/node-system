#pragma once
#include "include/library-pch.hpp"
#include "utils/utils.hpp"
// ifdef windows include win
// else include posix
#ifdef _WIN32
#include "include/win.hpp"
#else
#include "include/posix.hpp"
#endif

namespace node_system
{
    
    class Socket : non_copyable_movable
    {
    public:
        Socket();
        ~Socket();

        void bind(std::string_view address, uint16_t port);

        void listen();

        void accept();

        void connect(std::string_view address, uint16_t port);

        void send(char const* data, size_t size);

        void receive(char* data, size_t size);

        void close();

        bool is_open() const;

    private:
        int socket_;
    };
    
} // namespace node_system