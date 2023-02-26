#pragma once
#include "packet.hpp"
namespace node_system
{
    class PingPacket : public DerivedPacket<class PingPacket> {
    public:
        static constexpr uint32_t static_type = static_cast<uint32_t>(NetworkPacketType::PING);
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }

    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
            ar& boost::serialization::base_object<DerivedPacket<class PingPacket>>(*this);
        }
    };

    class PongPacket : public DerivedPacket<class PongPacket> {
    public:
        static constexpr uint32_t static_type = static_cast<uint32_t>(NetworkPacketType::PONG);
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }

    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
            ar& boost::serialization::base_object<DerivedPacket<class PongPacket>>(*this);
        }
    };

    template <>
    class PacketFactorySubsystem<PacketSubsystemType::NETWORK> {
    public:
        static std::unique_ptr<Packet> deserialize(ByteView buffer, uint32_t packet_type) {
            switch (static_cast<NetworkPacketType>(packet_type)) {
            case NetworkPacketType::PING:
                return DerivedPacket<PingPacket>::deserialize(buffer);
            case NetworkPacketType::PONG:
                return DerivedPacket<PongPacket>::deserialize(buffer);
            }
            return nullptr;
        }
    };
}