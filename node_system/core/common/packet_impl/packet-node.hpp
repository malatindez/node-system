#pragma once
#include "packet.hpp"
namespace node_system
{
    class NodeInfoPacket : public DerivedPacket<class NodeInfoPacket> {
    public:
        static constexpr uint32_t static_type = static_cast<uint32_t>(NodePacketType::NODE_INFO_REQUEST);
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }

        // TODO:
        // implement
    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
            ar& boost::serialization::base_object<DerivedPacket<class NodeInfoPacket>>(*this);
        }
    };

    class NodeInfoResponsePacket : public DerivedPacket<class NodeInfoResponsePacket> {
    public:
        static constexpr uint32_t static_type = static_cast<uint32_t>(NodePacketType::NODE_INFO_RESPONSE);
        [[nodiscard]] Permission get_permission() const override { return Permission::L2_CORE_NODE; }
        // TODO:
        // implement
    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
            ar& boost::serialization::base_object<DerivedPacket<class NodeInfoResponsePacket>>(*this);
        }
    };

    template <>
    class PacketFactorySubsystem<PacketSubsystemType::NODE> {
    public:
        static std::unique_ptr<Packet> deserialize(const ByteView buffer, uint32_t packet_type) {
            switch (static_cast<NodePacketType>(packet_type)) {
            case NodePacketType::NODE_INFO_REQUEST:
                return DerivedPacket<NodeInfoPacket>::deserialize(buffer);
            case NodePacketType::NODE_INFO_RESPONSE:
                return DerivedPacket<NodeInfoResponsePacket>::deserialize(buffer);
            default:
                return nullptr;
            }
        }
    };
}