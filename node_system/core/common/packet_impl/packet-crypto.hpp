#pragma once
#include "packet.hpp"
namespace node_system
{
    class DHKeyExchangePacket : public DerivedPacket<class DHKeyExchangePacket> {
    public:
        static constexpr uint32_t static_type = static_cast<uint32_t>(CryptoPacketType::DH_KEY_EXCHANGE);
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }

        ByteArray public_key;

    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
            ar& boost::serialization::base_object<DerivedPacket<class DHKeyExchangePacket>>(*this);
            ar& public_key;
        }
    };

    class DHKeyExchangeResponsePacket : public DerivedPacket<class DHKeyExchangeResponsePacket> {
    public:
        static constexpr uint32_t static_type = static_cast<uint32_t>(CryptoPacketType::DH_KEY_EXCHANGE_RESPONSE);
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }

        ByteArray public_key;
        ByteArray salt;
    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
            ar& boost::serialization::base_object<DerivedPacket<class DHKeyExchangeResponsePacket>>(*this);
            ar& public_key;
            ar& salt;
        }
    };

    template <>
    class PacketFactorySubsystem<PacketSubsystemType::CRYPTO> {
    public:
        static std::unique_ptr<Packet> deserialize(const ByteView buffer, uint32_t packet_type) {
            switch (static_cast<CryptoPacketType>(packet_type)) {
            case CryptoPacketType::DH_KEY_EXCHANGE:
                return DerivedPacket<DHKeyExchangePacket>::deserialize(buffer);
            case CryptoPacketType::DH_KEY_EXCHANGE_RESPONSE:
                return DerivedPacket<DHKeyExchangeResponsePacket>::deserialize(buffer);
            default:
                return nullptr;
            }
        }
    };
}