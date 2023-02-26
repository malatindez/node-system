#pragma once
#include "packet-common.hpp"
#include "packet-crypto.hpp"
#include "packet-node.hpp"
#include "packet-network.hpp"
#include "packet-system.hpp"
namespace node_system
{
    class PacketFactory {
    public:
        static std::unique_ptr<Packet> deserialize(const ByteView bytearray, uint32_t packet_type) {
            PacketSubsystemType subsystem = Uint32ToPacketSubsystemType(packet_type);
            switch (subsystem) {
            case PacketSubsystemType::CRYPTO:
                return PacketFactorySubsystem<PacketSubsystemType::CRYPTO>::deserialize(bytearray, packet_type);
            case PacketSubsystemType::NODE:
                return PacketFactorySubsystem<PacketSubsystemType::NODE>::deserialize(bytearray, packet_type);
            case PacketSubsystemType::NETWORK:
                return PacketFactorySubsystem<PacketSubsystemType::NETWORK>::deserialize(bytearray, packet_type);
            case PacketSubsystemType::SYSTEM:
                return PacketFactorySubsystem<PacketSubsystemType::SYSTEM>::deserialize(bytearray, packet_type);
            default:
                return nullptr;
            }
        }
    };
}