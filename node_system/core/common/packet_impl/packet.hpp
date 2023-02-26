#pragma once
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/base_object.hpp>
#include "packet-common.hpp"
namespace node_system
{
    class Packet : public utils::non_copyable {
    private:
        static utils::Measurer<std::chrono::steady_clock> measurer;
    public:
        explicit Packet(const uint32_t type) : type(type), timestamp_{ measurer.elapsed() } {}
        Packet(Packet&&) = default;
        Packet& operator=(Packet&&) = default;
        virtual Permission get_permission() const = 0;

        virtual ~Packet() = default;
        virtual void serialize(ByteArray& buffer) const = 0;

        [[nodiscard]] float timestamp() const noexcept { return timestamp_; }

        // Holds information when the packet was forged (in seconds)
        // not serializable
        const uint32_t type;
    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version)
        {
            ar& timestamp_;
        }
        float timestamp_;
    };

    template<typename Derived>
    class DerivedPacket : public Packet {
    public:
        DerivedPacket() : Packet(static_cast<uint32_t>(Derived::static_type)) {}
        void serialize(ByteArray& buffer) const override {
            std::ostringstream oss;
            boost::archive::binary_oarchive oa(oss);
            oa << static_cast<const Derived&>(*this);
            std::string const& s = oss.str();
            buffer.append(s);
        }

        static std::unique_ptr<Packet> deserialize(const ByteView buffer) {
            const auto char_view = buffer.as<char>();
            const std::string s(char_view, buffer.size());
            std::istringstream iss(s);
            boost::archive::binary_iarchive ia(iss);
            std::unique_ptr<Derived> derived_packet(new Derived);
            ia >> *derived_packet;
            return derived_packet;
        }

    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
            ar& boost::serialization::base_object<Packet>(*this);
        }
    };
} // namespace node_system