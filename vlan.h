#pragma once
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct vlan_tag
        {
            uint_least16_t tpid = 0x8100;
            unsigned char pcp{};
            bool dei{};
            uint_least16_t vid{};
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::vlan_tag& vlan)noexcept
    {
        if (last - first < 4)
        {
            return { first, std::errc::invalid_argument };
        }
        uint_least16_t tpid = (uint_least16_t)first[0] * 256 + (uint_least16_t)first[1];
        if (tpid != 0x8100 && tpid != 0x88a8)
        {
            return { first, std::errc::invalid_argument };
        }
        uint_least16_t tci = (uint_least16_t)first[2] * 256 + (uint_least16_t)first[3];
        vlan.tpid = tpid;
        vlan.pcp = (unsigned char)(tci >> 13);
        vlan.dei = (bool)((tci >> 12) & 1);
        vlan.vid = tci & 0x0fff;
        return { first + 4, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::vlan_tag vlan)noexcept
    {
        if (last - first < 4)
        {
            return { first, std::errc::value_too_large };
        }
        if (vlan.pcp > 7 || vlan.vid > 0x0fff)
        {
            return { first, std::errc::invalid_argument };
        }
        to_bytes(first, last, uint16_bytes(vlan.tpid));
        uint_least16_t tci = ((uint_least16_t)vlan.pcp << 13) | ((uint_least16_t)(vlan.dei ? 1 : 0) << 12) | vlan.vid;
        to_bytes(first + 2, last, uint16_bytes(tci));
        return { first + 4, {} };
    }
}
