#pragma once
#include <cstddef>
#include <cstdint>
#include <system_error>
namespace Yc
{
    struct from_bytes_result
    {
        const std::byte* ptr{};
        std::errc ec{};
        explicit constexpr operator bool()const noexcept
        {
            return ec == std::errc{};
        }
    };

    struct to_bytes_result
    {
        std::byte* ptr{};
        std::errc ec{};
        explicit constexpr operator bool()const noexcept
        {
            return ec == std::errc{};
        }
    };

    enum class uint16_bytes : uint_least16_t {};
    enum class uint32_bytes : uint_least32_t {};

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, std::byte& b)noexcept
    {
        if (first == last)
        {
            return { first, std::errc::invalid_argument };
        }
        b = *first;
        return { first + 1, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, std::byte b)noexcept
    {
        if (first == last)
        {
            return { first, std::errc::value_too_large };
        }
        *first = b;
        return { first + 1, {} };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, uint16_bytes& b)noexcept
    {
        if (last - first < 2)
        {
            return { last, std::errc::invalid_argument };
        }
        uint_least16_t ret = (unsigned int)(first[1]) + 256 * (unsigned int)(first[0]);
        b = uint16_bytes{ ret };
        return { first + 2, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, uint16_bytes b)noexcept
    {
        if (last - first < 2)
        {
            return { first, std::errc::value_too_large };
        }
        uint_least16_t val = (uint_least16_t)b;
        first[0] = std::byte(val / 256);
        first[1] = std::byte(val % 256);
        return { first + 2, {} };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, uint32_bytes& b)noexcept
    {
        if (last - first < 4)
        {
            return { last, std::errc::invalid_argument };
        }
        uint_least32_t low = (unsigned int)(first[3]) + 256 * (unsigned int)(first[2]);
        uint_least32_t high = (unsigned int)(first[1]) + 256 * (unsigned int)(first[0]);
        uint_least32_t ret = low + high * 256 * 256;
        b = uint32_bytes{ ret };
        return { first + 4, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, uint32_bytes b)noexcept
    {
        if (last - first < 4)
        {
            return { first, std::errc::value_too_large };
        }
        uint_least32_t high = (uint_least32_t)b / (256 * 256);
        uint_least32_t low = (uint_least32_t)b % (256 * 256);

        first[0] = std::byte(high / 256);
        first[1] = std::byte(high % 256);
        first[2] = std::byte(low / 256);
        first[3] = std::byte(low % 256);

        return { first + 4, {} };
    }
}