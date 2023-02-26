#pragma once
#include "packet.hpp"
namespace node_system
{
    utils::Measurer<std::chrono::steady_clock> Packet::measurer;
}