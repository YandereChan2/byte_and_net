#pragma once
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct icmp_echo
        {
            enum type_t : unsigned char
            {
                echo_reply = 0,
                destination_unreachable = 3,
                echo_request = 8,
                time_exceeded = 11,
            };
            type_t type{};
            unsigned char code{};
            uint_least16_t checksum{};
            uint_least16_t identifier{};
            uint_least16_t sequence{};
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::icmp_echo& icmp)noexcept
    {
        if (last - first < 8)
        {
            return { first, std::errc::invalid_argument };
        }
        icmp.type = (net::icmp_echo::type_t)(unsigned char)first[0];
        icmp.code = (unsigned char)first[1];
        icmp.checksum = (uint_least16_t)first[2] * 256 + (uint_least16_t)first[3];
        icmp.identifier = (uint_least16_t)first[4] * 256 + (uint_least16_t)first[5];
        icmp.sequence = (uint_least16_t)first[6] * 256 + (uint_least16_t)first[7];
        return { first + 8, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::icmp_echo icmp)noexcept
    {
        if (last - first < 8)
        {
            return { first, std::errc::value_too_large };
        }
        first[0] = (std::byte)(icmp.type);
        first[1] = (std::byte)(icmp.code);
        to_bytes(first + 2, last, uint16_bytes(0));
        to_bytes(first + 4, last, uint16_bytes(icmp.identifier));
        to_bytes(first + 6, last, uint16_bytes(icmp.sequence));
        return { first + 8, {} };
    }
}
