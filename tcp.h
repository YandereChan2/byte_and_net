#pragma once
#include <algorithm>
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct tcp_info
        {
            enum flag_t : unsigned char
            {
                fin = 0x01,
                syn = 0x02,
                rst = 0x04,
                psh = 0x08,
                ack = 0x10,
                urg = 0x20,
                ece = 0x40,
                cwr = 0x80,
            };
            port_t source_port{};
            port_t dest_port{};
            uint_least32_t sequence{};
            uint_least32_t ack_number{};
            size_t data_offset{};
            unsigned char flags{};
            uint_least16_t window{};
            uint_least16_t checksum{};
            uint_least16_t urgent{};
            size_t option_length{};
            std::byte options[40]{};
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::tcp_info& tcp)noexcept
    {
        if (last - first < 20)
        {
            return { first, std::errc::invalid_argument };
        }
        tcp.source_port = (net::port_t)(uint_least16_t)((uint_least16_t)first[0] * 256 + (uint_least16_t)first[1]);
        tcp.dest_port = (net::port_t)(uint_least16_t)((uint_least16_t)first[2] * 256 + (uint_least16_t)first[3]);
        tcp.sequence = (uint_least32_t)first[4] * 256 * 256 * 256 + (uint_least32_t)first[5] * 256 * 256 +
            (uint_least32_t)first[6] * 256 + (uint_least32_t)first[7];
        tcp.ack_number = (uint_least32_t)first[8] * 256 * 256 * 256 + (uint_least32_t)first[9] * 256 * 256 +
            (uint_least32_t)first[10] * 256 + (uint_least32_t)first[11];
        size_t data_offset = (size_t)first[12] / 16;
        if (data_offset < 5)
        {
            return { first, std::errc::invalid_argument };
        }
        tcp.data_offset = data_offset * 4;
        tcp.option_length = tcp.data_offset - 20;
        size_t head_len = tcp.data_offset;
        if (last - first < head_len || head_len > 60)
        {
            return { first, std::errc::invalid_argument };
        }
        tcp.flags = (unsigned char)first[13];
        tcp.window = (uint_least16_t)first[14] * 256 + (uint_least16_t)first[15];
        tcp.checksum = (uint_least16_t)first[16] * 256 + (uint_least16_t)first[17];
        tcp.urgent = (uint_least16_t)first[18] * 256 + (uint_least16_t)first[19];
        std::copy(first + 20, first + head_len, tcp.options);
        return { first + head_len, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::tcp_info tcp)noexcept
    {
        size_t head_len = tcp.data_offset;
        if (head_len < 20 || head_len > 60 || head_len % 4 != 0 || last - first < head_len)
        {
            return { first, std::errc::value_too_large };
        }
        if (tcp.option_length != head_len - 20 || (uint_least16_t)tcp.source_port > 65535 ||
            (uint_least16_t)tcp.dest_port > 65535 || tcp.window > 65535 || tcp.urgent > 65535)
        {
            return { first, std::errc::invalid_argument };
        }
        to_bytes(first, last, uint16_bytes((uint_least16_t)tcp.source_port));
        to_bytes(first + 2, last, uint16_bytes((uint_least16_t)tcp.dest_port));
        to_bytes(first + 4, last, uint32_bytes(tcp.sequence));
        to_bytes(first + 8, last, uint32_bytes(tcp.ack_number));
        first[12] = (std::byte)(head_len / 4 * 16);
        first[13] = (std::byte)(tcp.flags);
        to_bytes(first + 14, last, uint16_bytes(tcp.window));
        to_bytes(first + 16, last, uint16_bytes(tcp.checksum));
        to_bytes(first + 18, last, uint16_bytes(tcp.urgent));
        std::copy(tcp.options, tcp.options + tcp.option_length, first + 20);
        return { first + head_len, {} };
    }
}
