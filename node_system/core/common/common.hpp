#pragma once
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/base_object.hpp>
#include <boost/serialization/vector.hpp>
#include <span>
#include <vector>
#include <cstddef>
namespace node_system
{
    struct ByteView : public std::span<const std::byte>
    {
        using std::span<const std::byte>::span;
        using std::span<const std::byte>::operator=;
        using std::span<const std::byte>::operator[];
        template <typename T>
        [[nodiscard]] const T* as() const
        {
            return reinterpret_cast<const T*>(data());
        }
        [[nodiscard]] constexpr ByteView subview(size_t from = 0) const
        {
            return ByteView{ data() + from, size() - from };
        }
        [[nodiscard]] constexpr ByteView subview(size_t from, size_t length) const
        {
            return ByteView{ data() + from, length };
        }
    };

    struct ByteArray : public std::vector<std::byte>
    {
        using std::vector<std::byte>::vector;
        using std::vector<std::byte>::operator=;
        using std::vector<std::byte>::operator[];
        template <typename T>
        [[nodiscard]] constexpr T* as()
        {
            return reinterpret_cast<T*>(data());
        }
        template <typename T>
        [[nodiscard]] constexpr const T* as() const
        {
            return reinterpret_cast<const T*>(data());
        }

        [[nodiscard]] constexpr ByteView as_view() const
        {
            return ByteView{ data(), size() };
        }

        template<typename First, typename Second, typename... Args>
        void append(First&& first, typename Second&& second, Args&&... args)
        {
            append(std::forward<First>(first));
            append(std::forward<Second>(second));
            append(args...);
        }
        template<typename First, typename Second>
        void append(First&& first, typename Second&& second)
        {
            append(std::forward<First>(first));
            append(std::forward<Second>(second));
        }
        template<typename T> requires (sizeof(T) == sizeof(std::byte))
            void append(const std::vector<T>& other)
        {
            reserve(size() + other.size());
            if constexpr (std::is_trivially_constructible_v<std::byte, T>)
            {
                insert(end(), other.begin(), other.end());
            }
            else
            {
                std::transform(other.begin(), other.end(), std::back_inserter(*this), [](const T& t) { return static_cast<std::byte>(t); });
            }
        }
        template<typename T> requires (sizeof(T) == sizeof(std::byte))
            void append(const std::span<T>& other)
        {
            reserve(size() + other.size());
            if constexpr (std::is_trivially_constructible_v<std::byte, T>)
            {
                insert(end(), other.begin(), other.end());
            }
            else
            {
                std::transform(other.begin(), other.end(), std::back_inserter(*this), [](const T& t) { return static_cast<std::byte>(t); });
            }
        }

        template<typename T> requires (sizeof(T) == sizeof(std::byte))
            void append(const std::basic_string<T>& other)
        {
            reserve(size() + other.size());
            if constexpr (std::is_trivially_constructible_v<std::byte, T>)
            {
                insert(end(), other.begin(), other.end());
            }
            else
            {
                std::transform(other.begin(), other.end(), std::back_inserter(*this), [](const T& t) { return static_cast<std::byte>(t); });
            }
        }

        template <typename T> requires (sizeof(T) == sizeof(std::byte))
            void append(const std::basic_string_view<T>& other)
        {
            reserve(size() + other.size());
            if constexpr (std::is_trivially_constructible_v<std::byte, T>)
            {
                insert(end(), other.begin(), other.end());
            }
            else
            {
                std::transform(other.begin(), other.end(), std::back_inserter(*this), [](const T& t) { return static_cast<std::byte>(t); });
            }
        }

        template<typename... Args>
        static ByteArray from_byte_arrays(Args&&... args)
        {
            ByteArray result;
            result.append(std::forward<Args>(args)...);
            return result;
        }
        // Other conversions are forbidden, because of alignment/endianness and compiler features on other systems/compilers.
        // Even here you should convert integer taking into account endianness!
        template<std::integral Integer>
        static ByteArray from_integral(const Integer integer)
        {
            ByteArray rv;
            rv.resize(sizeof(Integer));
            *rv.as<Integer>() = integer;
            return rv;
        }

        [[nodiscard]] constexpr ByteView view(size_t from = 0) const
        {
            return ByteView{ data() + from, size() - from };
        }
        [[nodiscard]] constexpr ByteView view(size_t from, size_t length) const
        {
            return ByteView{ data() + from, length };
        }
    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive& ar, [[maybe_unused]] const unsigned int version)
        {
            ar& boost::serialization::base_object<std::vector<std::byte>>(*this);
        }
    };
}