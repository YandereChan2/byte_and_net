#pragma once
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct udp_info
        {
            port_t source_port{};
            port_t dest_port{};
            uint_least16_t length{};
            uint_least16_t checksum{};
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::udp_info& udp)noexcept
    {
        if (last - first < 8)
        {
            return { first, std::errc::invalid_argument };
        }
        udp.source_port = (net::port_t)(uint_least16_t)((uint_least16_t)first[0] * 256 + (uint_least16_t)first[1]);
        udp.dest_port = (net::port_t)(uint_least16_t)((uint_least16_t)first[2] * 256 + (uint_least16_t)first[3]);
        udp.length = (uint_least16_t)first[4] * 256 + (uint_least16_t)first[5];
        udp.checksum = (uint_least16_t)first[6] * 256 + (uint_least16_t)first[7];
        return { first + 8, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::udp_info udp)noexcept
    {
        if (last - first < 8)
        {
            return { first, std::errc::value_too_large };
        }
        to_bytes(first, last, uint16_bytes((uint_least16_t)udp.source_port));
        to_bytes(first + 2, last, uint16_bytes((uint_least16_t)udp.dest_port));
        to_bytes(first + 4, last, uint16_bytes(udp.length));
        to_bytes(first + 6, last, uint16_bytes(udp.checksum));
        return { first + 8, {} };
    }
}
