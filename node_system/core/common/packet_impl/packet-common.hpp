#pragma once
#include "../common.hpp"
#include <memory>
#include "../../utils/utils.hpp"



namespace node_system
{
    // Subsystem where to redirect the packet
    enum class PacketSubsystemType : uint32_t
    {
        // Crypto
        CRYPTO = 0x0001UL << 16,
        // Node
        NODE = 0x0002UL << 16,
        // Network
        NETWORK = 0x0003UL << 16,
        // System
        SYSTEM = 0x0004UL << 16,
        // Unknown
        UNKNOWN = 0x0005UL << 16
    };

    constexpr uint32_t PacketSubsystemTypeToUint32(PacketSubsystemType subsystem_type) noexcept
    {
        return utils::as_integer(subsystem_type);
    }

    constexpr PacketSubsystemType Uint32ToPacketSubsystemType(uint32_t subsystem_type) noexcept
    {
        return static_cast<PacketSubsystemType>(subsystem_type & 0xFFFF0000);
    }

    enum class CryptoPacketType : uint32_t
    {
        /**
         * @brief Will be used to initialize the connection
         * Using this packet, the client will send the public key to the server
         * The server will respond with the public key, salt, hash type and nrounds
         * with DH_KEY_EXCHANGE_RESPONSE.
         * This way we can initialize the connection
         */
        DH_KEY_EXCHANGE = 0000UL + utils::as_integer(PacketSubsystemType::CRYPTO),
        DH_KEY_EXCHANGE_RESPONSE = 0001UL + utils::as_integer(PacketSubsystemType::CRYPTO)
    };
    enum class NodePacketType : uint32_t
    {
        NODE_INFO = 0000UL + utils::as_integer(PacketSubsystemType::NODE),
        NODE_INFO_RESPONSE = 0001UL + utils::as_integer(PacketSubsystemType::NODE),
    };
    enum class NetworkPacketType : uint32_t
    {
        PING = 0000UL + utils::as_integer(PacketSubsystemType::NETWORK),
        PONG = 0001UL + utils::as_integer(PacketSubsystemType::NETWORK),
    };
    enum class SystemPacketType : uint32_t
    {
        SYSTEM_INFO = 0000UL + utils::as_integer(PacketSubsystemType::SYSTEM),
        SYSTEM_INFO_RESPONSE = 0001UL + utils::as_integer(PacketSubsystemType::SYSTEM),
    };

    enum class Permission : uint32_t
    {
        ANY = 0x0000UL,
        L1_NODE = 0x0001UL,
        L2_CORE_NODE = 0x0002UL,
        L2_PUBLIC_NODE = 0x0003UL,
        L2_ADMIN_NODE = 0x0004UL
    };

    template <PacketSubsystemType subsystem>
    class PacketFactorySubsystem;
}