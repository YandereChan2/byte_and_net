#pragma once
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct arp_info
        {
            enum operation_t : uint_least16_t
            {
                request = 1,
                reply = 2,
            };
            uint_least16_t hardware_type = 1;
            uint_least16_t protocol_type = 0x0800;
            unsigned char hardware_addr_len = 6;
            unsigned char protocol_addr_len = 4;
            operation_t operation{};
            mac_address_t sender_mac;
            ipv4_address_t sender_ip;
            mac_address_t target_mac;
            ipv4_address_t target_ip;
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::arp_info& arp)noexcept
    {
        if (last - first < 28)
        {
            return { first, std::errc::invalid_argument };
        }
        if ((uint_least16_t)first[0] * 256 + (uint_least16_t)first[1] != 1 ||
            (uint_least16_t)first[2] * 256 + (uint_least16_t)first[3] != 0x0800 ||
            (unsigned char)first[4] != 6 || (unsigned char)first[5] != 4)
        {
            return { first, std::errc::invalid_argument };
        }
        arp.hardware_type = 1;
        arp.protocol_type = 0x0800;
        arp.hardware_addr_len = 6;
        arp.protocol_addr_len = 4;
        arp.operation = (net::arp_info::operation_t)(uint_least16_t)((uint_least16_t)first[6] * 256 + (uint_least16_t)first[7]);
        arp.sender_mac = net::mac_address_t{ (unsigned char)first[8], (unsigned char)first[9], (unsigned char)first[10],
            (unsigned char)first[11], (unsigned char)first[12], (unsigned char)first[13] };
        arp.sender_ip = net::ipv4_address_t{ (unsigned char)first[14], (unsigned char)first[15],
            (unsigned char)first[16], (unsigned char)first[17] };
        arp.target_mac = net::mac_address_t{ (unsigned char)first[18], (unsigned char)first[19], (unsigned char)first[20],
            (unsigned char)first[21], (unsigned char)first[22], (unsigned char)first[23] };
        arp.target_ip = net::ipv4_address_t{ (unsigned char)first[24], (unsigned char)first[25],
            (unsigned char)first[26], (unsigned char)first[27] };
        return { first + 28, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::arp_info arp)noexcept
    {
        if (last - first < 28)
        {
            return { first, std::errc::value_too_large };
        }
        to_bytes(first, last, uint16_bytes(arp.hardware_type));
        to_bytes(first + 2, last, uint16_bytes(arp.protocol_type));
        first[4] = std::byte{ arp.hardware_addr_len };
        first[5] = std::byte{ arp.protocol_addr_len };
        to_bytes(first + 6, last, uint16_bytes((uint_least16_t)arp.operation));
        to_bytes(first + 8, last, arp.sender_mac);
        to_bytes(first + 14, last, arp.sender_ip);
        to_bytes(first + 18, last, arp.target_mac);
        to_bytes(first + 24, last, arp.target_ip);
        return { first + 28, {} };
    }
}
