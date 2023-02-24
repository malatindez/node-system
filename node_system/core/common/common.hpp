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
        [[nodiscard]] const T *as() const
        {
            return reinterpret_cast<const T *>(data());
        }
    };

    struct ByteArray : public std::vector<std::byte>
    {
        using std::vector<std::byte>::vector;
        using std::vector<std::byte>::operator=;
        using std::vector<std::byte>::operator[];
        template <typename T>
        [[nodiscard]] T *as()
        {
            return reinterpret_cast<T *>(data());
        }
        template <typename T>
        [[nodiscard]] const T *as() const
        {
            return reinterpret_cast<const T *>(data());
        }

        [[nodiscard]] ByteView as_view() const
        {
            return ByteView{data(), size()};
        }
    };
}