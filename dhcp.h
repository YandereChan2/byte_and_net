#pragma once
#include <algorithm>
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct dhcp_info
        {
            enum op_t : unsigned char
            {
                boot_request = 1,
                boot_reply = 2,
            };
            op_t op{};
            unsigned char htype = 1;
            unsigned char hlen = 6;
            unsigned char hops{};
            uint_least32_t xid{};
            uint_least16_t secs{};
            uint_least16_t flags{};
            ipv4_address_t ciaddr;
            ipv4_address_t yiaddr;
            ipv4_address_t siaddr;
            ipv4_address_t giaddr;
            mac_address_t chaddr;
            std::byte sname[64]{};
            std::byte file[128]{};
            size_t options_len{};
            std::byte options[312]{};
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::dhcp_info& dhcp)noexcept
    {
        if (last - first < 240)
        {
            return { first, std::errc::invalid_argument };
        }
        dhcp.op = (net::dhcp_info::op_t)(unsigned char)first[0];
        dhcp.htype = (unsigned char)first[1];
        dhcp.hlen = (unsigned char)first[2];
        dhcp.hops = (unsigned char)first[3];
        dhcp.xid = (uint_least32_t)first[4] * 256 * 256 * 256 + (uint_least32_t)first[5] * 256 * 256 +
            (uint_least32_t)first[6] * 256 + (uint_least32_t)first[7];
        dhcp.secs = (uint_least16_t)first[8] * 256 + (uint_least16_t)first[9];
        dhcp.flags = (uint_least16_t)first[10] * 256 + (uint_least16_t)first[11];
        dhcp.ciaddr = net::ipv4_address_t{ (unsigned char)first[12], (unsigned char)first[13],
            (unsigned char)first[14], (unsigned char)first[15] };
        dhcp.yiaddr = net::ipv4_address_t{ (unsigned char)first[16], (unsigned char)first[17],
            (unsigned char)first[18], (unsigned char)first[19] };
        dhcp.siaddr = net::ipv4_address_t{ (unsigned char)first[20], (unsigned char)first[21],
            (unsigned char)first[22], (unsigned char)first[23] };
        dhcp.giaddr = net::ipv4_address_t{ (unsigned char)first[24], (unsigned char)first[25],
            (unsigned char)first[26], (unsigned char)first[27] };
        dhcp.chaddr = net::mac_address_t{ (unsigned char)first[28], (unsigned char)first[29],
            (unsigned char)first[30], (unsigned char)first[31], (unsigned char)first[32], (unsigned char)first[33] };
        std::copy(first + 44, first + 108, dhcp.sname);
        std::copy(first + 108, first + 236, dhcp.file);
        size_t avail = (size_t)(last - first);
        dhcp.options_len = 0;
        if (avail >= 244)
        {
            uint_least32_t magic = (uint_least32_t)first[236] * 256 * 256 * 256 +
                (uint_least32_t)first[237] * 256 * 256 + (uint_least32_t)first[238] * 256 + (uint_least32_t)first[239];
            if (magic == 0x63825363)
            {
                size_t max_opt = avail - 240;
                if (max_opt > sizeof(dhcp.options)) max_opt = sizeof(dhcp.options);
                std::copy(first + 240, first + 240 + max_opt, dhcp.options);
                dhcp.options_len = max_opt;
            }
        }
        return { first + 240 + dhcp.options_len, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::dhcp_info dhcp)noexcept
    {
        size_t total = 240 + dhcp.options_len;
        if (total > sizeof(dhcp.options) + 240 || last - first < total)
        {
            return { first, std::errc::value_too_large };
        }
        first[0] = (std::byte)(dhcp.op);
        first[1] = (std::byte)(dhcp.htype);
        first[2] = (std::byte)(dhcp.hlen);
        first[3] = (std::byte)(dhcp.hops);
        to_bytes(first + 4, last, uint32_bytes(dhcp.xid));
        to_bytes(first + 8, last, uint16_bytes(dhcp.secs));
        to_bytes(first + 10, last, uint16_bytes(dhcp.flags));
        to_bytes(first + 12, last, dhcp.ciaddr);
        to_bytes(first + 16, last, dhcp.yiaddr);
        to_bytes(first + 20, last, dhcp.siaddr);
        to_bytes(first + 24, last, dhcp.giaddr);
        to_bytes(first + 28, last, dhcp.chaddr);
        std::fill(first + 34, first + 44, std::byte{});
        std::copy(dhcp.sname, dhcp.sname + 64, first + 44);
        std::copy(dhcp.file, dhcp.file + 128, first + 108);
        to_bytes(first + 236, last, uint32_bytes(0x63825363));
        std::copy(dhcp.options, dhcp.options + dhcp.options_len, first + 240);
        return { first + total, {} };
    }
}
