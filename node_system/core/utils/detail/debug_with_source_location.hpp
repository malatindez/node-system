#pragma once
#include "../debug.hpp"
namespace utils
{
    inline std::string CurrentSourceLocation(std::source_location location = std::source_location::current())
    {
        std::stringstream ss;
        ss << "[" << location.file_name() << "] ";
        ss << location.function_name() << "(line " << location.line() << ", column " << location.column() << ") ";
        return ss.str();
    }
    // asserts only in debug
    inline void Assert(bool value, std::string_view message = "Assert failed", std::source_location location = std::source_location::current())
    {
        if constexpr (!DEBUG_UTILS_ASSERT_ENABLED)
        {
            return;
        }

        if (value) [[likely]]
        {
            return;
        }

            if constexpr (DEBUG_UTILS_ASSERT_LOGS)
            {
                spdlog::critical(CurrentSourceLocation(location) + std::basic_string(message));
            }
        if constexpr (DEBUG_UTILS_FORCE_ASSERT)
        {
            assert(value);
        }
        else
        {
            if constexpr (DEBUG_UTILS_ASSERT_ABORTS)
            {
                std::abort();
            }
            else
            {
                throw std::runtime_error(CurrentSourceLocation(location) + std::basic_string(message));
            }
        }
    }

    inline void AlwaysAssert(bool value, std::string_view message = "Assert failed", std::source_location location = std::source_location::current())
    {
        if constexpr (!DEBUG_UTILS_ALWAYS_ASSERT_ENABLED)
        {
            return;
        }

        if (value) [[likely]]
        {
            return;
        }

            if constexpr (DEBUG_UTILS_ASSERT_LOGS)
            {
                spdlog::critical(CurrentSourceLocation(location) + std::basic_string(message));
            }

        if constexpr (DEBUG_UTILS_FORCE_ASSERT)
        {
            assert(value);
        }
        else
        {
            if constexpr (DEBUG_UTILS_ASSERT_ABORTS)
            {
                std::abort();
            }
            else
            {
                throw std::runtime_error(CurrentSourceLocation(location) + std::basic_string(message));
            }
        }
    }
}