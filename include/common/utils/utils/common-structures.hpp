#pragma once
#include "include/library-pch.hpp"
namespace utils
{
    /// @brief A class that can't be copied
    class non_copyable
    {
    public:
        non_copyable() = default;
        non_copyable(const non_copyable &) = delete;
        non_copyable &operator=(const non_copyable &) = delete;
    };
    /// @brief A class that can't be moved
    class non_movable
    {
    public:
        non_movable() = default;
        non_movable(non_movable &&) = delete;
        non_movable &operator=(non_movable &&) = delete;
    };
    /// @brief A class that can't be copied neither moved
    class non_copyable_movable : public non_copyable, public non_movable
    {
    public:
        non_copyable_movable() = default;
    };
    /**
     * @brief A class that contains a name and can be named and unnamed
     * @note This class is constexpr compatible
     */
    class namable
    {
    public:
        namable() = default;
        constexpr explicit namable(std::string const &name) : name_(name) {}
        constexpr explicit namable(std::string &&name) : name_(std::move(name)) {}
        ~namable() = default;

        constexpr void set_name(std::string const &name) { name_ = name; }
        constexpr void set_name(std::string &&name) { name_ = std::move(name); }
        constexpr void clear_name() { name_.clear(); }
        constexpr bool has_name() const { return !name_.empty(); }
        [[nodiscard]] constexpr std::string_view name() const { return name_; }

    private:
        std::string name_;
    };
    /**
     * @brief A class that contains a name and can be named and unnamed, but you cant set the name from outside
     * @note This class is constexpr compatible
     */
    class namable_protected : public namable
    {
    public:
        namable_protected() = default;
        constexpr explicit namable_protected(std::string const &name) : namable(name) {}
        constexpr explicit namable_protected(std::string &&name) : namable(std::move(name)) {}
        ~namable_protected() = default;
    protected:
        using namable::set_name;
        using namable::clear_name;
    };
    /**
     * @brief A class that contains a name and can be named only once at construction
     * @note This class is constexpr compatible
     * @note You can't change the name after construction
     */
    class namable_once : private namable
    {
    public:
        constexpr explicit namable_once(std::string const &name) : namable(name) {}
        constexpr explicit namable_once(std::string &&name) : namable(std::move(name)) {}
        ~namable_once() = default;
        using namable::has_name;
        using namable::name;
    };
    /**
     * @brief A class that can be enabled or disabled
     * @note This class is constexpr compatible
     */
    class enableable
    {
    public:
        enableable() = default;
        ~enableable() = default;

        constexpr void enable() { enabled_ = true; }
        constexpr void disable() { enabled_ = false; }
        constexpr bool is_enabled() const { return enabled_; }
        constexpr bool is_disabled() const { return !enabled_; }

        constexpr bool enabled() const { return enabled_; }
    private:
        bool enabled_ = true;
    };
} // namespace utils