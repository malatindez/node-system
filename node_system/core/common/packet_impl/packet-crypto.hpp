#pragma once
#include "packet.hpp"
#include "core/crypto/common.hpp"
#include "core/crypto/sha.hpp"
namespace node_system
{
    class DHKeyExchangePacket : public DerivedPacket<class DHKeyExchangePacket> {
    public:
        static constexpr uint32_t static_type = static_cast<uint32_t>(CryptoPacketType::DH_KEY_EXCHANGE_REQUEST);
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
        [[nodiscard]] crypto::Hash get_hash() const
        {
            ByteArray arr;
            arr.append(public_key, salt, ByteArray::from_integral(boost::endian::little_to_native(static_type)));
            return crypto::SHA::ComputeHash(arr, crypto::Hash::HashType::SHA256);
        }

        ByteArray public_key;
        ByteArray salt;
        int n_rounds;

        // Signature of the public key, salt and n_rounds.
        ByteArray signature;
    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
            ar& boost::serialization::base_object<DerivedPacket<class DHKeyExchangeResponsePacket>>(*this);
            ar& public_key;
            ar& signature;
            ar& salt;
            ar& n_rounds;
        }
    };

    template <>
    class PacketFactorySubsystem<PacketSubsystemType::CRYPTO> {
    public:
        static std::unique_ptr<Packet> deserialize(const ByteView buffer, uint32_t packet_type) {
            switch (static_cast<CryptoPacketType>(packet_type)) {
            case CryptoPacketType::DH_KEY_EXCHANGE_REQUEST:
                return DerivedPacket<DHKeyExchangePacket>::deserialize(buffer);
            case CryptoPacketType::DH_KEY_EXCHANGE_RESPONSE:
                return DerivedPacket<DHKeyExchangeResponsePacket>::deserialize(buffer);
            default:
                return nullptr;
            }
        }
    };
}