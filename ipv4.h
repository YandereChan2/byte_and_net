#pragma once
#include <algorithm>
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct ipv4_info
        {
            size_t option_length{};
            enum type_of_service_t : unsigned char
            {
            }type_of_service{};
            size_t data_len{};
            unsigned int tag{};
            bool df{};
            bool mf{};
            size_t data_offset{};
            unsigned char time_to_live{ 255 };
            enum protocol_t : unsigned char
            {
                icmp = 1,
                tcp = 6,
                udp = 17,
            }protocol;
            ipv4_address_t source;
            ipv4_address_t dest;
            std::byte optional[40]{};
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::ipv4_info& iphdr)noexcept
    {
        if (last - first < 20)
        {
            return { first, std::errc::invalid_argument };
        }
        net::ipv4_info ret{};
        // 校验版本号和长度
        unsigned char fb = (unsigned char)*first;
        if (fb / 16 != 4 || (fb % 16) < 5)
        {
            return { first, std::errc::invalid_argument };
        }
        ret.option_length = static_cast<size_t>((fb % 16)) * 4 - 20;
        size_t head_len = ret.option_length + 20;
        if (last - first < head_len)
        {
            return { first, std::errc::invalid_argument };
        }
        uint_least32_t sum{};
        for (const std::byte* b{ first }; b != first + head_len; b += 2)
        {
            sum += (uint_least32_t)b[0] * 256 + (uint_least32_t)b[1];
        }
        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        if (sum != 0xFFFF)
        {
            return { first, std::errc::invalid_argument };
        }
        if ((size_t)first[2] * 256 + (size_t)first[3] < head_len)
        {
            return { first, std::errc::invalid_argument };
        }
        ret.type_of_service = (net::ipv4_info::type_of_service_t)(unsigned char)first[1];
        ret.data_len = (size_t)first[2] * 256 + (size_t)first[3] - head_len;
        ret.tag = (unsigned int)first[4] * 256 + (unsigned int)first[5];
        ret.df = (bool)(first[6] & (std::byte)0b01000000);
        ret.mf = (bool)(first[6] & (std::byte)0b00100000);
        ret.data_offset = (((size_t)first[6] * 256 + (size_t)first[7]) & 0b0001111111111111) * 8;
        ret.time_to_live = (unsigned char)first[8];
        ret.protocol = (net::ipv4_info::protocol_t)first[9];
        from_bytes(first + 12, last, ret.source);
        from_bytes(first + 16, last, ret.dest);
        std::copy(first + 20, first + head_len, ret.optional);
        iphdr = ret;
        return { first + head_len, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::ipv4_info iphdr)noexcept
    {
        size_t head_len = iphdr.option_length + 20;
        if (head_len > 60 || last - first < head_len)
        {
            return { first, std::errc::value_too_large };
        }
        if (head_len % 4 != 0 ||
            iphdr.data_len > (65535 - head_len) ||
            iphdr.data_offset % 8 != 0 ||
            iphdr.data_offset > 0b0001111111111111 * 8 ||
            iphdr.time_to_live == 0 ||
            iphdr.tag > 65535)
        {
            return { first, std::errc::invalid_argument };
        }
        first[0] = (std::byte)(4 * 16 + head_len / 4);
        first[1] = (std::byte)(iphdr.type_of_service);
        to_bytes(first + 2, last, Yc::uint16_bytes(head_len + iphdr.data_len));
        to_bytes(first + 4, last, Yc::uint16_bytes(iphdr.tag));
        to_bytes(first + 6, last, Yc::uint16_bytes(
            (iphdr.df ? 0b0100000000000000 : 0) | (iphdr.mf ? 0b0010000000000000 : 0) | (iphdr.data_offset / 8)
        ));
        first[8] = (std::byte)(iphdr.time_to_live);
        first[9] = (std::byte)(iphdr.protocol);
        first[10] = std::byte{};
        first[11] = std::byte{};
        to_bytes(first + 12, last, iphdr.source);
        to_bytes(first + 16, last, iphdr.dest);
        std::copy(iphdr.optional, iphdr.optional + iphdr.option_length, first + 20);
        uint_least32_t sum{};
        for (const std::byte* b{ first }; b != first + head_len; b += 2)
        {
            sum += (uint_least32_t)b[0] * 256 + (uint_least32_t)b[1];
        }
        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        to_bytes(first + 10, first + 12, Yc::uint16_bytes(~sum));
        return { first + head_len, {} };
    }
}
