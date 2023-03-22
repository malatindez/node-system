#pragma once
#include "packet.hpp"
namespace node_system
{
    class SystemInfoPacket : public DerivedPacket<class SystemInfoPacket> {
    public:
        static constexpr uint32_t static_type = static_cast<uint32_t>(SystemPacketType::SYSTEM_INFO_REQUEST);
        [[nodiscard]] Permission get_permission() const override { return Permission::L2_CORE_NODE; }
        // TODO:
        // implement
    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
            ar& boost::serialization::base_object<DerivedPacket<class SystemInfoPacket>>(*this);
        }
    };

    class SystemInfoResponsePacket : public DerivedPacket<class SystemInfoResponsePacket> {
    public:
        static constexpr uint32_t static_type = static_cast<uint32_t>(SystemPacketType::SYSTEM_INFO_RESPONSE);
        [[nodiscard]] Permission get_permission() const override { return Permission::L2_CORE_NODE; }
        // TODO:
        // implement
    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
            ar& boost::serialization::base_object<DerivedPacket<class SystemInfoResponsePacket>>(*this);
        }
    };

    template <>
    class PacketFactorySubsystem<PacketSubsystemType::SYSTEM> {
    public:
        static std::unique_ptr<Packet> deserialize(ByteView buffer, uint32_t packet_type) {
            switch (static_cast<SystemPacketType>(packet_type)) {
            case SystemPacketType::SYSTEM_INFO_REQUEST:
                return DerivedPacket<SystemInfoPacket>::deserialize(buffer);
            case SystemPacketType::SYSTEM_INFO_RESPONSE:
                return DerivedPacket<SystemInfoResponsePacket>::deserialize(buffer);
            default:
                return nullptr;
            }
        }
    };
}