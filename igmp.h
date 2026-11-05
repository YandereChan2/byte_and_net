#pragma once
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct igmp_info
        {
            enum type_t : unsigned char
            {
                membership_query = 0x11,
                v1_report = 0x12,
                v2_report = 0x16,
                v3_report = 0x22,
                leave = 0x17,
            };
            type_t type{};
            unsigned char max_resp_time{};
            uint_least16_t checksum{};
            uint_least32_t group_address{};
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::igmp_info& igmp)noexcept
    {
        if (last - first < 8)
        {
            return { first, std::errc::invalid_argument };
        }
        igmp.type = (net::igmp_info::type_t)(unsigned char)first[0];
        igmp.max_resp_time = (unsigned char)first[1];
        igmp.checksum = (uint_least16_t)first[2] * 256 + (uint_least16_t)first[3];
        igmp.group_address = (uint_least32_t)first[4] * 256 * 256 * 256 + (uint_least32_t)first[5] * 256 * 256 +
            (uint_least32_t)first[6] * 256 + (uint_least32_t)first[7];
        return { first + 8, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::igmp_info igmp)noexcept
    {
        if (last - first < 8)
        {
            return { first, std::errc::value_too_large };
        }
        first[0] = (std::byte)(igmp.type);
        first[1] = (std::byte)(igmp.max_resp_time);
        to_bytes(first + 2, last, uint16_bytes(0));
        to_bytes(first + 4, last, uint32_bytes(igmp.group_address));
        return { first + 8, {} };
    }
}
