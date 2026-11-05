#pragma once
#include "byteconv.h"
#include "ip.h"

namespace Yc
{
    namespace net
    {
        struct dns_info
        {
            uint_least16_t transaction_id{};
            uint_least16_t flags{};
            uint_least16_t questions{};
            uint_least16_t answers{};
            uint_least16_t authority_rrs{};
            uint_least16_t additional_rrs{};
        };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::dns_info& dns)noexcept
    {
        if (last - first < 12)
        {
            return { first, std::errc::invalid_argument };
        }
        dns.transaction_id = (uint_least16_t)first[0] * 256 + (uint_least16_t)first[1];
        dns.flags = (uint_least16_t)first[2] * 256 + (uint_least16_t)first[3];
        dns.questions = (uint_least16_t)first[4] * 256 + (uint_least16_t)first[5];
        dns.answers = (uint_least16_t)first[6] * 256 + (uint_least16_t)first[7];
        dns.authority_rrs = (uint_least16_t)first[8] * 256 + (uint_least16_t)first[9];
        dns.additional_rrs = (uint_least16_t)first[10] * 256 + (uint_least16_t)first[11];
        return { first + 12, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::dns_info dns)noexcept
    {
        if (last - first < 12)
        {
            return { first, std::errc::value_too_large };
        }
        to_bytes(first, last, uint16_bytes(dns.transaction_id));
        to_bytes(first + 2, last, uint16_bytes(dns.flags));
        to_bytes(first + 4, last, uint16_bytes(dns.questions));
        to_bytes(first + 6, last, uint16_bytes(dns.answers));
        to_bytes(first + 8, last, uint16_bytes(dns.authority_rrs));
        to_bytes(first + 10, last, uint16_bytes(dns.additional_rrs));
        return { first + 12, {} };
    }
}
