#pragma once
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct ethernet_header
        {
            mac_address_t dest;
            mac_address_t source;
            uint_least16_t ether_type{};
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::ethernet_header& eth)noexcept
    {
        if (last - first < 14)
        {
            return { first, std::errc::invalid_argument };
        }
        eth.dest = net::mac_address_t{ (unsigned char)first[0], (unsigned char)first[1], (unsigned char)first[2],
            (unsigned char)first[3], (unsigned char)first[4], (unsigned char)first[5] };
        eth.source = net::mac_address_t{ (unsigned char)first[6], (unsigned char)first[7], (unsigned char)first[8],
            (unsigned char)first[9], (unsigned char)first[10], (unsigned char)first[11] };
        eth.ether_type = (uint_least16_t)first[12] * 256 + (uint_least16_t)first[13];
        return { first + 14, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::ethernet_header eth)noexcept
    {
        if (last - first < 14)
        {
            return { first, std::errc::value_too_large };
        }
        to_bytes(first, last, eth.dest);
        to_bytes(first + 6, last, eth.source);
        to_bytes(first + 12, last, uint16_bytes(eth.ether_type));
        return { first + 14, {} };
    }
}
