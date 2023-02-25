#pragma once
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
    };

    struct ByteArray : public std::vector<std::byte>
    {
        using std::vector<std::byte>::vector;
        using std::vector<std::byte>::operator=;
        using std::vector<std::byte>::operator[];
        template <typename T>
        [[nodiscard]] T* as()
        {
            return reinterpret_cast<T*>(data());
        }
        template <typename T>
        [[nodiscard]] const T* as() const
        {
            return reinterpret_cast<const T*>(data());
        }

        [[nodiscard]] ByteView as_view() const
        {
            return ByteView{ data(), size() };
        }

        template<typename First, typename Second, typename... Args>
        void append(First&& first, typename Second second, Args&&... args)
        {
            append(std::forward<First>(first));
            append(std::forward<Second>(second));
            append(args...);
        }
        template<typename First, typename Second>
        void append(First&& first, typename Second second)
        {
            append(std::forward<First>(first));
            append(std::forward<Second>(second));
        }
        void append(const ByteArray& other)
        {
            reserve(size() + other.size());
            insert(end(), other.begin(), other.end());
        }
        void append(const ByteView& other)
        {
            reserve(size() + other.size());
            insert(end(), other.begin(), other.end());
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

        ByteView view(size_t from = 0) const
        {
            return ByteView{ data() + from, size() - from };
        }
        ByteView view(size_t from, size_t length) const
        {
            return ByteView{ data() + from, length };
        }
    };
}