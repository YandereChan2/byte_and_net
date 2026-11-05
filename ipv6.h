#pragma once
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct ipv6_info
        {
            enum next_header_t : unsigned char
            {
                hop_by_hop = 0,
                icmpv6 = 58,
                tcp = 6,
                udp = 17,
                routing = 43,
                fragment = 44,
                esp = 50,
                ah = 51,
                no_next = 59,
                dest_opt = 60,
            };
            unsigned char traffic_class{};
            uint_least32_t flow_label{};
            uint_least16_t payload_length{};
            next_header_t next_header{};
            unsigned char hop_limit{ 64 };
            ipv6_address_t source;
            ipv6_address_t dest;
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::ipv6_info& iphdr)noexcept
    {
        if (last - first < 40)
        {
            return { first, std::errc::invalid_argument };
        }
        uint_least32_t vtf = (uint_least32_t)first[0] * 256 * 256 * 256 + (uint_least32_t)first[1] * 256 * 256 +
            (uint_least32_t)first[2] * 256 + (uint_least32_t)first[3];
        if (vtf >> 28 != 6)
        {
            return { first, std::errc::invalid_argument };
        }
        iphdr.traffic_class = (unsigned char)((vtf >> 20) & 0xff);
        iphdr.flow_label = vtf & 0x000fffff;
        iphdr.payload_length = (uint_least16_t)first[4] * 256 + (uint_least16_t)first[5];
        iphdr.next_header = (net::ipv6_info::next_header_t)(unsigned char)first[6];
        iphdr.hop_limit = (unsigned char)first[7];
        iphdr.source = net::ipv6_address_t{
            (unsigned char)first[8], (unsigned char)first[9], (unsigned char)first[10], (unsigned char)first[11],
            (unsigned char)first[12], (unsigned char)first[13], (unsigned char)first[14], (unsigned char)first[15],
            (unsigned char)first[16], (unsigned char)first[17], (unsigned char)first[18], (unsigned char)first[19],
            (unsigned char)first[20], (unsigned char)first[21], (unsigned char)first[22], (unsigned char)first[23] };
        iphdr.dest = net::ipv6_address_t{
            (unsigned char)first[24], (unsigned char)first[25], (unsigned char)first[26], (unsigned char)first[27],
            (unsigned char)first[28], (unsigned char)first[29], (unsigned char)first[30], (unsigned char)first[31],
            (unsigned char)first[32], (unsigned char)first[33], (unsigned char)first[34], (unsigned char)first[35],
            (unsigned char)first[36], (unsigned char)first[37], (unsigned char)first[38], (unsigned char)first[39] };
        return { first + 40, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::ipv6_info iphdr)noexcept
    {
        if (last - first < 40)
        {
            return { first, std::errc::value_too_large };
        }
        uint_least32_t vtf = ((uint_least32_t)6 << 28) | ((uint_least32_t)iphdr.traffic_class << 20) | (iphdr.flow_label & 0x000fffff);
        to_bytes(first, last, uint32_bytes(vtf));
        to_bytes(first + 4, last, uint16_bytes(iphdr.payload_length));
        first[6] = (std::byte)(iphdr.next_header);
        first[7] = (std::byte)(iphdr.hop_limit);
        to_bytes(first + 8, last, iphdr.source);
        to_bytes(first + 24, last, iphdr.dest);
        return { first + 40, {} };
    }
}
