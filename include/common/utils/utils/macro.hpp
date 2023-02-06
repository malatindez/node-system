#pragma once
/**
 * @brief This macro is used to declare the bitwise operators for an enum class so it is easier to use it as a bitfield
 * @note This macro is used when the underlying type of the enum class is not the default one
 */
#define ENGINE_UTILS_DECLARE_ENUM_BIT_OPERATORS_EX(ENUM_TYPE, ENUM_TYPE_UNDERLYING) \
inline ENUM_TYPE operator|(ENUM_TYPE a, ENUM_TYPE b) \
{ \
    return static_cast<ENUM_TYPE>(static_cast<ENUM_TYPE_UNDERLYING>(a) | static_cast<ENUM_TYPE_UNDERLYING>(b)); \
} \
inline ENUM_TYPE operator&(ENUM_TYPE a, ENUM_TYPE b) \
{ \
    return static_cast<ENUM_TYPE>(static_cast<ENUM_TYPE_UNDERLYING>(a) & static_cast<ENUM_TYPE_UNDERLYING>(b)); \
} \
inline ENUM_TYPE operator^(ENUM_TYPE a, ENUM_TYPE b) \
{ \
    return static_cast<ENUM_TYPE>(static_cast<ENUM_TYPE_UNDERLYING>(a) ^ static_cast<ENUM_TYPE_UNDERLYING>(b)); \
} \
inline ENUM_TYPE operator~(ENUM_TYPE a) \
{ \
    return static_cast<ENUM_TYPE>(~static_cast<ENUM_TYPE_UNDERLYING>(a)); \
} \
inline ENUM_TYPE &operator|=(ENUM_TYPE &a, ENUM_TYPE b) \
{ \
    return a = a | b; \
} \
inline ENUM_TYPE &operator&=(ENUM_TYPE &a, ENUM_TYPE b) \
{ \
    return a = a & b; \
} \
inline ENUM_TYPE &operator^=(ENUM_TYPE &a, ENUM_TYPE b) \
{ \
    return a = a ^ b; \
} \
inline bool operator!(ENUM_TYPE a) \
{ \
    return !static_cast<ENUM_TYPE_UNDERLYING>(a); \
} \
template <std::integral T> \
inline ENUM_TYPE operator|(ENUM_TYPE a, T b) \
{ \
    return a | static_cast<ENUM_TYPE>(b); \
} \
template <std::integral T> \
inline ENUM_TYPE operator&(ENUM_TYPE a, T b) \
{ \
    return a & static_cast<ENUM_TYPE>(b); \
} \
template <std::integral T> \
inline ENUM_TYPE operator^(ENUM_TYPE a, T b) \
{ \
    return a ^ static_cast<ENUM_TYPE>(b); \
} \
template <std::integral T> \
inline ENUM_TYPE &operator|=(ENUM_TYPE &a, T b) \
{ \
    return a = a | b; \
} \
template <std::integral T> \
inline ENUM_TYPE &operator&=(ENUM_TYPE &a, T b) \
{ \
    return a = a & b; \
} \
template <std::integral T> \
inline ENUM_TYPE &operator^=(ENUM_TYPE &a, T b) \
{ \
    return a = a ^ b; \
} \
template <std::integral T> \
inline ENUM_TYPE operator|(T a, ENUM_TYPE b) \
{ \
    return static_cast<ENUM_TYPE>(a) | b; \
} \
template <std::integral T> \
inline ENUM_TYPE operator&(T a, ENUM_TYPE b) \
{ \
    return static_cast<ENUM_TYPE>(a) & b; \
} \
template <std::integral T> \
inline ENUM_TYPE operator^(T a, ENUM_TYPE b) \
{ \
    return static_cast<ENUM_TYPE>(a) ^ b; \
}
/**
 * @brief This macro is used to declare the bitwise operators for an enum class so it is easier to use it as a bitfield
 */
#define ENGINE_UTILS_DECLARE_ENUM_BIT_OPERATORS(ENUM_TYPE) \
ENGINE_UTILS_DECLARE_ENUM_BIT_OPERATORS_EX(ENUM_TYPE, std::underlying_type_t<ENUM_TYPE>)

/**
 * @brief This macro is used to declare the bitwise functions for an enum class so it is easier to use it as a bitfield
 */
#define ENGINE_UTILS_DECLARE_ENUM_BIT_FUNCTIONS(ENUM_TYPE) \
template<typename T> \
inline bool HasFlag(ENUM_TYPE a, T b) \
{ \
    return (a & b) == b; \
} \
template<typename T> \
inline bool HasAnyFlag(ENUM_TYPE a, T b) \
{ \
    return (a & b) != 0; \
} \
template<typename T> \
inline bool HasAllFlags(ENUM_TYPE a, T b) \
{ \
    return (a & b) == a; \
} \
template<typename T> \
inline ENUM_TYPE SetFlag(ENUM_TYPE a, T b) \
{ \
    return a | b; \
} \
template<typename T> \
inline ENUM_TYPE ClearFlag(ENUM_TYPE a, T b) \
{ \
    return a & ~b; \
} \
template<typename T> \
inline ENUM_TYPE FlipFlag(ENUM_TYPE a, T b) \
{ \
    return a ^ b; \
}

#define ENGINE_UTILS_DECLARE_ENUM_BIT_OPERATORS_AND_FUNCTIONS(ENUM_TYPE) \
ENGINE_UTILS_DECLARE_ENUM_BIT_OPERATORS(ENUM_TYPE) \
ENGINE_UTILS_DECLARE_ENUM_BIT_FUNCTIONS(ENUM_TYPE)