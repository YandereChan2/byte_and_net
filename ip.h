#pragma once
#include <cstdint>
#include <algorithm>
#include <string_view>
#include <exception>
#include <stdexcept>
#include <charconv>
#include <array>
#include <format>
#include <bit>
#include <istream>
#include <ostream>
#include <string>
#include "byteconv.h"
#include <cstddef>
namespace Yc
{
    namespace net
    {
        using mac_diff_t = int_least64_t;

        class mac_address_t
        {
            unsigned char addr[6]{};
            template<bool lower_case>
            static constexpr unsigned char char2u8(char h, char l)
            {
                constexpr char a = lower_case ? 'a' : 'A';
                constexpr char f = lower_case ? 'f' : 'F';
                unsigned char ret = 0;
                if (h >= '0' && h <= '9')
                {
                    ret += (h - '0') * 16;
                }
                else if (h >= a && h <= f)
                {
                    ret += (h - a + 10) * 16;
                }
                else
                {
                    throw std::invalid_argument{ "parse mac str failed!" };
                }

                if (l >= '0' && l <= '9')
                {
                    ret += l - '0';
                }
                else if (l >= a && l <= f)
                {
                    ret += l - a + 10;
                }
                else
                {
                    throw std::invalid_argument{ "parse mac str failed!" };
                }
                return ret;
            }

            static constexpr uint_least64_t mac_to_u48(mac_address_t mac)noexcept
            {
                return ((uint_least64_t)mac.addr[0] << 40) | ((uint_least64_t)mac.addr[1] << 32) |
                    ((uint_least64_t)mac.addr[2] << 24) | ((uint_least64_t)mac.addr[3] << 16) |
                    ((uint_least64_t)mac.addr[4] << 8) | (uint_least64_t)mac.addr[5];
            }

            static constexpr mac_address_t u48_to_mac(uint_least64_t v)noexcept
            {
                return { (unsigned char)(v >> 40), (unsigned char)(v >> 32), (unsigned char)(v >> 24),
                    (unsigned char)(v >> 16), (unsigned char)(v >> 8), (unsigned char)v };
            }
        public:
            constexpr mac_address_t() = default;
            constexpr mac_address_t(const mac_address_t&) = default;
            constexpr mac_address_t& operator=(const mac_address_t&) = default;
            constexpr mac_address_t(std::nullptr_t)noexcept {};
            constexpr mac_address_t(unsigned char a, unsigned char b, unsigned char c,
                unsigned char d, unsigned char e, unsigned char f)noexcept :addr{ a, b, c, d, e, f }
            {
            }

            // 构造函数支持 xx:xx:xx:xx:xx:xx 或 xx-xx-xx-xx-xx-xx
            // 自动判断大小写模式，但不可混用
            constexpr mac_address_t(std::string_view str)
            {
                // 判断长度
                if (str.size() != 17)
                {
                    throw std::invalid_argument{ "parse mac str failed!" };
                }
                // 分隔符是否合法
                if (str[2] != ':' && str[2] != '-')
                {
                    throw std::invalid_argument{ "parse mac str failed!" };
                }
                // 分隔符必须一致
                for (auto i : { 5, 8, 11, 14 })
                {
                    if (str[2] != str[i])
                    {
                        throw std::invalid_argument{ "parse mac str failed!" };
                    }
                }
                // 确定是小写模式还是大写模式
                bool lower_case = std::any_of(str.begin(), str.end(), [](char c) { return c >= 'a' && c <= 'f'; });
                if (lower_case)
                {
                    for (auto i : { 0, 3, 6, 9, 12, 15 })
                    {
                        addr[i / 3] = char2u8<true>(str[i], str[i + 1]);
                    }
                }
                else
                {
                    for (auto i : { 0, 3, 6, 9, 12, 15 })
                    {
                        addr[i / 3] = char2u8<false>(str[i], str[i + 1]);
                    }
                }
            }

            constexpr operator bool()const noexcept
            {
                return *this != mac_address_t{};
            }

            constexpr static mac_address_t broadcast_address()noexcept
            {
                return { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
            }

            constexpr static mac_address_t cdp_vtp_address()noexcept
            {
                return { 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc };
            }

            constexpr static mac_address_t mdns_address()noexcept
            {
                return { 0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb };
            }

            constexpr static mac_address_t stp_address()noexcept
            {
                return { 0x01, 0x80,0xc2,0,0,0 };
            }

            constexpr static mac_address_t eps_address()noexcept
            {
                return { 0x01, 0x80,0xc2,0,0,1 };
            }

            constexpr static mac_address_t lacp_address()noexcept
            {
                return { 0x01, 0x80,0xc2,0,0,2 };
            }

            constexpr static mac_address_t port_auth_address()noexcept
            {
                return { 0x01, 0x80,0xc2,0,0,3 };
            }

            constexpr static mac_address_t mstp_address()noexcept
            {
                return { 0x01, 0x80,0xc2,0,0,8 };
            }

            constexpr static mac_address_t lldp_address()noexcept
            {
                return { 0x01, 0x80,0xc2,0,0,0x0e };
            }

            constexpr bool is_broadcast()const noexcept
            {
                return *this == broadcast_address();
            }

            constexpr bool is_unspecified_or_any()const noexcept
            {
                return !*this;
            }

            constexpr bool is_multicast()const noexcept
            {
                return ((addr[0] & 1) == 1) && (*this != broadcast_address());
            }

            constexpr bool is_unicast()const noexcept
            {
                return ((addr[0] & 1) == 0) && (*this != mac_address_t{});
            }

            constexpr bool is_public()const noexcept
            {
                return ((addr[0] & 2) == 0) && *this;
            }

            constexpr bool is_local_administered()const noexcept
            {
                return ((addr[0] & 2) != 0) && (*this != broadcast_address());
            }

            constexpr bool is_ipv4_multicast()const noexcept
            {
                return addr[0] == 0x01 && addr[1] == 0x00 && addr[2] == 0x5e && ((addr[3] & 0x80) == 0);
            }

            constexpr bool is_ipv6_multicast()const noexcept
            {
                return addr[0] == 0x33 && addr[1] == 0x33;
            }

            constexpr std::array<unsigned char, 6> underlying()const noexcept
            {
                return { addr[0], addr[1], addr[2], addr[3], addr[4], addr[5] };
            }

            friend bool operator==(mac_address_t, mac_address_t) = default;

            friend constexpr std::to_chars_result to_chars(char* first, char* last, mac_address_t value)noexcept;
            friend constexpr std::from_chars_result from_chars(const char* first, const char* last, mac_address_t& value)noexcept;

            constexpr mac_address_t& operator+=(mac_diff_t diff)noexcept
            {
                *this = u48_to_mac((mac_diff_t)mac_to_u48(*this) + diff);
                return *this;
            }

            constexpr mac_address_t& operator-=(mac_diff_t diff)noexcept
            {
                *this = u48_to_mac((mac_diff_t)mac_to_u48(*this) - diff);
                return *this;
            }

            constexpr mac_address_t& operator++()noexcept
            {
                return *this += 1;
            }

            constexpr mac_address_t operator++(int)noexcept
            {
                mac_address_t tmp = *this;
                ++*this;
                return tmp;
            }

            constexpr mac_address_t& operator--()noexcept
            {
                return *this -= 1;
            }

            constexpr mac_address_t operator--(int)noexcept
            {
                mac_address_t tmp = *this;
                --*this;
                return tmp;
            }

            constexpr friend mac_address_t operator+(mac_address_t mac, mac_diff_t diff)noexcept
            {
                return mac += diff;
            }

            constexpr friend mac_address_t operator+(mac_diff_t diff, mac_address_t mac)noexcept
            {
                return mac += diff;
            }

            constexpr friend mac_address_t operator-(mac_address_t mac, mac_diff_t diff)noexcept
            {
                return mac -= diff;
            }

            constexpr friend mac_diff_t operator-(mac_address_t l, mac_address_t r)noexcept
            {
                return (mac_diff_t)mac_to_u48(l) - (mac_diff_t)mac_to_u48(r);
            }

            constexpr friend auto operator<=>(mac_address_t l, mac_address_t r)noexcept
            {
                return mac_to_u48(l) <=> mac_to_u48(r);
            }

            constexpr mac_address_t operator*()const noexcept
            {
                return *this;
            }
        };

        struct mac_range
        {
            mac_address_t first;
            mac_address_t last;

            constexpr mac_address_t begin()const noexcept
            {
                return first;
            }

            constexpr mac_address_t end()const noexcept
            {
                return last;
            }
        };

        enum class port_t : uint_least16_t
        {
        };

        using ipv4_diff_t = int_least64_t;
        class ipv4_address_t
        {
            unsigned char addr[4]{};
            static constexpr uint_least32_t ipv4_to_u32(ipv4_address_t ip)noexcept
            {
                return ip.addr[0] * 256 * 256 * 256 + ip.addr[1] * 256 * 256 + ip.addr[2] * 256 + ip.addr[3];
            }
            static constexpr ipv4_address_t u32_to_ipv4(uint_least32_t v)noexcept
            {
                return { (unsigned char)(v / (256 * 256 * 256)), (unsigned char)(v / (256 * 256)),
                    (unsigned char)(v / 256), (unsigned char)v };
            }
        public:
            ipv4_address_t() = default;
            ipv4_address_t(const ipv4_address_t&) = default;
            ipv4_address_t& operator=(const ipv4_address_t&) = default;
            friend constexpr bool operator==(ipv4_address_t, ipv4_address_t) = default;
            constexpr ipv4_address_t(std::string_view str)
            {
                if (str.size() > 15)
                {
                    throw std::invalid_argument{ "parse ip str failed!" };
                }
                const char* first = str.data();
                const char* last = first + str.size();
                auto ec = std::from_chars(first, last, addr[0]);
                if (ec.ec != std::errc{} || addr[0] >= 256)
                {
                    throw std::invalid_argument{ "parse ip str failed!" };
                }
                first = ec.ptr;
                if (first == last || *first != '.')
                {
                    throw std::invalid_argument{ "parse ip str failed!" };
                }
                ++first;
                ec = std::from_chars(first, last, addr[1]);
                if (ec.ec != std::errc{} || addr[1] >= 256)
                {
                    throw std::invalid_argument{ "parse ip str failed!" };
                }
                first = ec.ptr;
                if (first == last || *first != '.')
                {
                    throw std::invalid_argument{ "parse ip str failed!" };
                }
                ++first;
                ec = std::from_chars(first, last, addr[2]);
                if (ec.ec != std::errc{} || addr[2] >= 256)
                {
                    throw std::invalid_argument{ "parse ip str failed!" };
                }
                first = ec.ptr;
                if (first == last || *first != '.')
                {
                    throw std::invalid_argument{ "parse ip str failed!" };
                }
                ++first;
                ec = std::from_chars(first, last, addr[3]);
                if (ec.ec != std::errc{} || addr[3] >= 256)
                {
                    throw std::invalid_argument{ "parse ip str failed!" };
                }
                first = ec.ptr;
                if (first != last)
                {
                    throw std::invalid_argument{ "parse ip str failed!" };
                }
            }

            constexpr ipv4_address_t(unsigned char a, unsigned char b, unsigned char c, unsigned char d)noexcept:addr{a, b, c, d}
            { }

            constexpr ipv4_address_t(std::nullptr_t)noexcept:ipv4_address_t{}
            { }

            constexpr bool operator==(std::nullptr_t)const noexcept
            {
                return !operator bool();
            }

            constexpr explicit operator bool()const noexcept
            {
                return *this != ipv4_address_t{};
            }

            // 10.0.0.0 - 10.255.255.255
            constexpr bool is_private_A()const noexcept
            {
                return addr[0] == 10;
            }

            // 172.16.0.0 - 172.31.255.255
            constexpr bool is_private_B()const noexcept
            {
                return addr[0] == 172 && addr[1] >= 16 && addr[1] <= 31;
            }

            // 192.168.0.0 - 192.168.255.255
            constexpr bool is_private_C()const noexcept
            {
                return addr[0] == 192 && addr[1] == 168;
            }

            constexpr bool is_private()const noexcept
            {
                return is_private_A() || is_private_B() || is_private_C();
            }

            // 127.0.0.0 - 127.255.255.255
            constexpr bool is_loopback()const noexcept
            {
                return addr[0] == 127;
            }

            // 224.0.0.0 - 239.255.255.255
            constexpr bool is_multicast()const noexcept
            {
                return addr[0] >= 224 && addr[0] <= 239;
            }

            // 169.254.0.0 - 169.254.255.255
            constexpr bool is_link_local()const noexcept
            {
                return addr[0] == 169 && addr[1] == 254;
            }

            // 192.0.2.0 - 192.0.2.255
            // 198.51.100.0 - 198.51.100.255
            // 203.0.113.0 - 203.0.113.255
            constexpr bool is_documentation()const noexcept
            {
                unsigned char a[]{ 192,0,2 };
                unsigned char b[]{ 198,51,100 };
                unsigned char c[]{ 203,0,113 };
                return std::equal(addr, addr + 3, a) || std::equal(addr, addr + 3, b) || std::equal(addr, addr + 3, c);
            }

            // 0.0.0.0 - 0.255.255.255
            constexpr bool is_this_network()const noexcept
            {
                return addr[0] == 0;
            }

            // 240.0.0.0 - 255.255.255.254
            constexpr bool is_reserved()const noexcept
            {
                return addr[0] >= 240 && *this != ipv4_address_t{ 255,255,255,255 };
            }

            constexpr bool is_broadcast()const noexcept
            {
                return *this == ipv4_address_t{ 255,255,255,255 };
            }

            constexpr bool is_unspecified_or_any()const noexcept
            {
                return !*this;
            }

            constexpr std::array<unsigned char, 4> underlying()const noexcept
            {
                return { addr[0], addr[1], addr[2], addr[3] };
            }

            constexpr uint_least32_t underlying_uint()const noexcept
            {
                std::array<unsigned char, sizeof(uint_least32_t)> ret{ addr[0], addr[1], addr[2], addr[3] };
                return std::bit_cast<uint_least32_t>(ret);
            }

            constexpr ipv4_address_t& operator+=(ipv4_diff_t diff)noexcept
            {
                *this = u32_to_ipv4((ipv4_diff_t)ipv4_to_u32(*this) + diff);
                return *this;
            }

            constexpr ipv4_address_t& operator-=(ipv4_diff_t diff)noexcept
            {
                *this = u32_to_ipv4((ipv4_diff_t)ipv4_to_u32(*this) - diff);
                return *this;
            }

            constexpr ipv4_address_t& operator++()noexcept
            {
                return *this+=1;
            }

            constexpr ipv4_address_t operator++(int)noexcept
            {
                ipv4_address_t tmp = *this;
                ++*this;
                return tmp;
            }

            constexpr ipv4_address_t& operator--()noexcept
            {
                return *this -= 1;
            }

            constexpr ipv4_address_t operator--(int)noexcept
            {
                ipv4_address_t tmp = *this;
                --*this;
                return tmp;
            }

            constexpr friend ipv4_address_t operator+(ipv4_address_t ip, ipv4_diff_t diff)noexcept
            {
                return ip += diff;
            }

            constexpr friend ipv4_address_t operator+(ipv4_diff_t diff, ipv4_address_t ip)noexcept
            {
                return ip += diff;
            }

            constexpr friend ipv4_address_t operator-(ipv4_address_t ip, ipv4_diff_t diff)noexcept
            {
                return ip -= diff;
            }

            constexpr friend ipv4_address_t operator-(ipv4_diff_t diff, ipv4_address_t ip)noexcept
            {
                return ip -= diff;
            }

            constexpr friend auto operator<=>(ipv4_address_t l, ipv4_address_t r)noexcept
            {
                return ipv4_to_u32(l) <=> ipv4_to_u32(r);
            }

            constexpr friend ipv4_diff_t operator-(ipv4_address_t l, ipv4_address_t r)noexcept
            {
                return (ipv4_diff_t)ipv4_to_u32(l) - (ipv4_diff_t)ipv4_to_u32(r);
            }
            friend std::istream& operator>>(std::istream& is, ipv4_address_t& ip)
            {
                ip = ipv4_address_t{};
                std::istream::sentry s(is);
                if (s)
                {
                    unsigned char result[4]{};
                    int c;
                    // 前三段字符处理逻辑一致
                    for (size_t i{}; i < 3; ++i)
                    {
                        c = is.peek();
                        
                        if (c == '0')
                        {
                            is.get();
                            result[i] = 0;
                            c = is.peek();
                        }
                        else if(c >= '3' && c <= '9')
                        {
                            // 读取一到两个数字
                            result[i] = (c - '0');
                            is.get();
                            c = is.peek();
                            if (c == '.')
                            {
                                is.get();
                                continue;
                            }
                            else if (c >= '0' && c <= '9')
                            {
                                result[i] *= 10;
                                result[i] += c - '0';
                                is.get();
                            }
                            else
                            {
                                is.setstate(std::ios::failbit);
                                return is;
                            }
                        }
                        else if (c == '1' || c == '2')
                        {
                            result[i] = (c - '0');
                            is.get();
                            c = is.peek();
                            if (c == '.')
                            {
                                is.get();
                                continue;
                            }
                            else if (c >= '0' && c <= '9')
                            {
                                result[i] *= 10;
                                result[i] += c - '0';
                                is.get();
                            }
                            else
                            {
                                is.setstate(std::ios::failbit);
                                return is;
                            }
                            c = is.peek();
                            if (c == '.')
                            {
                                is.get();
                                continue;
                            }
                            else if (c >= '0' && c <= '9')
                            {
                                if (result[i] > 25 || (result[i] == 25 && c >= '6'))
                                {
                                    // 溢出
                                    is.setstate(std::ios::failbit);
                                    return is;
                                }
                                result[i] *= 10;
                                result[i] += c - '0';
                                is.get();
                            }
                            else
                            {
                                is.setstate(std::ios::failbit);
                                return is;
                            }
                        }

                        c = is.peek();
                        if (c != '.')
                        {
                            is.setstate(std::ios::failbit);
                            return is;
                        }
                        is.get();
                    }

                    // 最后一段，注意后面不能接数字，可以是EOF或其他字符
                    c = is.peek();
                    if (c == '0')
                    {
                        result[3] = 0;
                        is.get();
                        c = is.peek();
                        if (c >= '0' && c <= '9')
                        {
                            is.setstate(std::ios::failbit);
                            return is;
                        }
                    }
                    else if (c >= '3' && c <= '9')
                    {
                        result[3] = (c - '0');
                        is.get();
                        c = is.peek();
                        if (c >= '0' && c <= '9')
                        {
                            result[3] *= 10;
                            result[3] += c - '0';
                            is.get();
                            c = is.peek();
                            if (c >= '0' && c <= '9')
                            {
                                is.setstate(std::ios::failbit);
                                return is;
                            }
                        }
                    }
                    else if (c == '1' || c == '2')
                    {
                        result[3] = (c - '0');
                        is.get();
                        c = is.peek();
                        if (c >= '0' && c <= '9')
                        {
                            result[3] *= 10;
                            result[3] += c - '0';
                            is.get();
                            c = is.peek();
                            if (c >= '0' && c <= '9')
                            {
                                if (result[3] > 25 || (result[3] == 25 && c >= '6'))
                                {
                                    // 溢出
                                    is.setstate(std::ios::failbit);
                                    return is;
                                }
                                result[3] *= 10;
                                result[3] += c - '0';
                                is.get();
                                c = is.peek();
                                if (c >= '0' && c <= '9')
                                {
                                    is.setstate(std::ios::failbit);
                                    return is;
                                }
                            }
                        }
                    }
                    ip = ipv4_address_t{result[0], result[1], result[2], result[3]};
                }
                return is;
            }
            friend constexpr std::to_chars_result to_chars(char* first, char* last, ipv4_address_t value)noexcept;
            friend std::ostream& operator<<(std::ostream& os, ipv4_address_t ip)
            {
                char buf[16]{};
                to_chars(buf, buf + 16, ip);
                return os << buf;
            }

            // 内置静态地址
            static constexpr inline ipv4_address_t any() noexcept              // 0.0.0.0
            {
                return ipv4_address_t{ 0, 0, 0, 0 };
            }

            static constexpr ipv4_address_t loopback() noexcept         // 127.0.0.1
            {
                return ipv4_address_t{ 127, 0, 0, 1 };
            }

            static constexpr ipv4_address_t broadcast() noexcept        // 255.255.255.255
            {
                return ipv4_address_t{ 255, 255, 255, 255 };
            }

            static constexpr ipv4_address_t localhost() noexcept        // 127.0.0.1 (同loopback)
            {
                return loopback();
            }
        };

        constexpr mac_address_t make_multicast_mac_addr(ipv4_address_t ip)
        {
            if (!ip.is_multicast())
            {
                throw std::invalid_argument{ "not multicast address" };
            }
            std::array<unsigned char, 4> u = ip.underlying();
            return { 0x01, 0x00, 0x5e, u[1] & 0x7F, u[2], u[3] };
        }

        constexpr std::to_chars_result to_chars(char* first, char* last, ipv4_address_t value)noexcept
        {
            char buffer[16]{};
            char* tmp = buffer;
            char* const end = buffer + 16;
            auto [a, b, c, d] = value.underlying();
            tmp = std::to_chars(tmp, end, a).ptr;
            *tmp = '.';
            ++tmp;
            tmp = std::to_chars(tmp, end, b).ptr;
            *tmp = '.';
            ++tmp;
            tmp = std::to_chars(tmp, end, c).ptr;
            *tmp = '.';
            ++tmp;
            tmp = std::to_chars(tmp, end, d).ptr;
            if (last - first < tmp - buffer)
            {
                return { last, std::errc::result_out_of_range };
            }
            return { std::copy(buffer, tmp, first), {}};
        }

        constexpr std::from_chars_result from_chars(const char* first, const char* last, ipv4_address_t& value)noexcept
        {
            if (last - first < 7)
            {
                return { first, std::errc::invalid_argument };
            }
            unsigned char a{}, b{}, c{}, d{};
            auto ec = std::from_chars(first, last, a);
            if (ec.ec != std::errc{} || a >= 256)
            {
                return { first, std::errc::invalid_argument };
            }
            first = ec.ptr;
            if (first == last || *first != '.')
            {
                return { first, std::errc::invalid_argument };
            }
            ++first;
            ec = std::from_chars(first, last, b);
            if (ec.ec != std::errc{} || b >= 256)
            {
                return { first, std::errc::invalid_argument };
            }
            first = ec.ptr;
            if (first == last || *first != '.')
            {
                return { first, std::errc::invalid_argument };
            }
            ++first;
            ec = std::from_chars(first, last, c);
            if (ec.ec != std::errc{} || c >= 256)
            {
                return { first, std::errc::invalid_argument };
            }
            first = ec.ptr;
            if (first == last || *first != '.')
            {
                return { first, std::errc::invalid_argument };
            }
            ++first;
            ec = std::from_chars(first, last, d);
            if (ec.ec != std::errc{} || d >= 256)
            {
                return { first, std::errc::invalid_argument };
            }
            value = ipv4_address_t{ a, b, c, d };
            first = ec.ptr;
            return { first, {} };
        }

        constexpr std::to_chars_result to_chars(char* first, char* last, mac_address_t value)noexcept
        {
            constexpr auto hex = std::array{ '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
            if (last - first < 17)
            {
                return { last, std::errc::result_out_of_range };
            }
            std::array<unsigned char, 6> u = value.underlying();
            for (size_t i = 0; i < 6; ++i)
            {
                *first++ = hex[u[i] >> 4];
                *first++ = hex[u[i] & 0xf];
                if (i < 5)
                {
                    *first++ = '-';
                }
            }
            return { first, {} };
        }

        constexpr std::from_chars_result from_chars(const char* first, const char* last, mac_address_t& value)noexcept
        {
            if (last - first < 12)
            {
                return { first, std::errc::invalid_argument };
            }
            constexpr auto hex_low = std::array{ '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
            constexpr auto hex_upp = std::array{ '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
            auto digit = [](char c) -> int
            {
                for (size_t k = 0; k < 16; ++k)
                {
                    if (hex_low[k] == c || hex_upp[k] == c)
                    {
                        return (int)k;
                    }
                }
                return -1;
            };
            auto read_byte = [&](const char* p) -> int
            {
                int hi = digit(p[0]);
                int lo = digit(p[1]);
                if (hi < 0 || lo < 0)
                {
                    return -1;
                }
                return hi * 16 + lo;
            };
            auto is_sep = [](char c) { return c == '-' || c == ':' || c == '.'; };
            unsigned char addr[6]{};
            const char* pos = first;
            if (is_sep(pos[2]))
            {
                char sep = pos[2];
                for (int i = 0; i < 6; ++i)
                {
                    int b = read_byte(pos);
                    if (b < 0)
                    {
                        return { pos, std::errc::invalid_argument };
                    }
                    addr[i] = (unsigned char)b;
                    pos += 2;
                    if (i < 5)
                    {
                        if (*pos != sep)
                        {
                            return { pos, std::errc::invalid_argument };
                        }
                        ++pos;
                    }
                }
            }
            else if (pos + 5 <= last && is_sep(pos[4]))
            {
                char sep = pos[4];
                for (int g = 0; g < 3; ++g)
                {
                    for (int j = 0; j < 2; ++j)
                    {
                        int b = read_byte(pos);
                        if (b < 0)
                        {
                            return { pos, std::errc::invalid_argument };
                        }
                        addr[g * 2 + j] = (unsigned char)b;
                        pos += 2;
                    }
                    if (g < 2)
                    {
                        if (*pos != sep)
                        {
                            return { pos, std::errc::invalid_argument };
                        }
                        ++pos;
                    }
                }
            }
            else
            {
                for (int i = 0; i < 6; ++i)
                {
                    int b = read_byte(pos);
                    if (b < 0)
                    {
                        return { pos, std::errc::invalid_argument };
                    }
                    addr[i] = (unsigned char)b;
                    pos += 2;
                }
            }
            value = mac_address_t{ addr[0], addr[1], addr[2], addr[3], addr[4], addr[5] };
            return { pos, {} };
        }

        namespace detail
        {
            enum class mac_fmt_style : int
            {
                hyphen_2,
                hyphen_4,
                colon_2,
                colon_4,
                dot_4,
                compact,
            };

            inline int mac_fmt_idx()
            {
                static int idx = std::ios_base::xalloc();
                return idx;
            }
        }

        inline std::ostream& mac_hyphen_2(std::ostream& os)
        {
            os.iword(detail::mac_fmt_idx()) = (long)detail::mac_fmt_style::hyphen_2;
            return os;
        }

        inline std::ostream& mac_hyphen_4(std::ostream& os)
        {
            os.iword(detail::mac_fmt_idx()) = (long)detail::mac_fmt_style::hyphen_4;
            return os;
        }

        inline std::ostream& mac_colon_2(std::ostream& os)
        {
            os.iword(detail::mac_fmt_idx()) = (long)detail::mac_fmt_style::colon_2;
            return os;
        }

        inline std::ostream& mac_colon_4(std::ostream& os)
        {
            os.iword(detail::mac_fmt_idx()) = (long)detail::mac_fmt_style::colon_4;
            return os;
        }

        inline std::ostream& mac_dot_4(std::ostream& os)
        {
            os.iword(detail::mac_fmt_idx()) = (long)detail::mac_fmt_style::dot_4;
            return os;
        }

        inline std::ostream& mac_compact(std::ostream& os)
        {
            os.iword(detail::mac_fmt_idx()) = (long)detail::mac_fmt_style::compact;
            return os;
        }

        inline std::ostream& operator<<(std::ostream& os, mac_address_t mac)
        {
            constexpr auto hex = std::array{ '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
            auto style = static_cast<detail::mac_fmt_style>(os.iword(detail::mac_fmt_idx()));
            char sep;
            int group;
            switch (style)
            {
            case detail::mac_fmt_style::hyphen_4: sep = '-'; group = 4; break;
            case detail::mac_fmt_style::colon_2:  sep = ':'; group = 2; break;
            case detail::mac_fmt_style::colon_4:  sep = ':'; group = 4; break;
            case detail::mac_fmt_style::dot_4:    sep = '.'; group = 4; break;
            case detail::mac_fmt_style::compact:  sep = 0;  group = 0; break;
            default:                              sep = '-'; group = 2; break;
            }
            std::array<unsigned char, 6> u = mac.underlying();
            char buf[18]{};
            char* out = buf;
            for (int i = 0; i < 6; ++i)
            {
                *out++ = hex[u[i] >> 4];
                *out++ = hex[u[i] & 0xf];
                if (i < 5 && sep != 0 && (i + 1) * 2 % group == 0)
                {
                    *out++ = sep;
                }
            }
            return os << buf;
        }

        class ipv6_address_t
        {
            unsigned char addr[16]{};
        public:
            ipv6_address_t() = default;
            ipv6_address_t(const ipv6_address_t&) = default;
            ipv6_address_t& operator=(const ipv6_address_t&) = default;
            friend bool operator==(ipv6_address_t, ipv6_address_t) = default;

            constexpr explicit operator bool()const noexcept
            {
                return *this != ipv6_address_t{};
            }

            constexpr friend auto operator<=>(ipv6_address_t l, ipv6_address_t r)noexcept
            {
                return std::lexicographical_compare_three_way(l.addr, l.addr + 16, r.addr, r.addr + 16);
            }

            constexpr bool operator==(std::nullptr_t)const noexcept
            {
                return !operator bool();
            }

            constexpr ipv6_address_t(std::string_view str)
            {
                auto [ptr, ec] = from_chars(str.data(), str.data() + str.size(), *this);
                if (ec != std::errc{})
                {
                    throw std::invalid_argument{ "parse ipv6 str failed!" };
                }
            }

            constexpr ipv6_address_t(uint_least32_t a, uint_least32_t b, uint_least32_t c, uint_least32_t d)noexcept:
                addr{   unsigned char(a >> 24), unsigned char(a >> 16) , unsigned char(a >> 8) , unsigned char(a), 
                        unsigned char(b >> 24), unsigned char(b >> 16) , unsigned char(b >> 8) , unsigned char(b),
                        unsigned char(c >> 24), unsigned char(c >> 16) , unsigned char(c >> 8) , unsigned char(c),
                        unsigned char(d >> 24), unsigned char(d >> 16) , unsigned char(d >> 8) , unsigned char(d),
                    }
            {
            }

            constexpr ipv6_address_t(   uint_least16_t a, uint_least16_t b, uint_least16_t c, uint_least16_t d,
                                        uint_least16_t e, uint_least16_t f, uint_least16_t g, uint_least16_t h)noexcept:
                addr{ unsigned char(a >> 8), unsigned char(a) , unsigned char(b >> 8) , unsigned char(b),
                        unsigned char(c >> 8), unsigned char(c) , unsigned char(d >> 8) , unsigned char(d),
                        unsigned char(e >> 8), unsigned char(e) , unsigned char(f >> 8) , unsigned char(f),
                        unsigned char(g >> 8), unsigned char(g) , unsigned char(h >> 8) , unsigned char(h),
            }
            {
            }

            constexpr ipv6_address_t(   unsigned char a01, unsigned char a02, unsigned char a03, unsigned char a04,
                                        unsigned char a05, unsigned char a06, unsigned char a07, unsigned char a08,
                                        unsigned char a09, unsigned char a10, unsigned char a11, unsigned char a12,
                                        unsigned char a13, unsigned char a14, unsigned char a15, unsigned char a16)noexcept :
                addr{ a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11, a12, a13, a14, a15, a16 }
            {
            }

            constexpr ipv6_address_t(std::nullptr_t)noexcept :ipv6_address_t{}
            {
            }

            constexpr bool is_unspecified_or_any()const noexcept
            {
                return !*this;
            }

            constexpr bool is_multicast()const noexcept
            {
                return addr[0] == 0xff;
            }

            constexpr std::array<unsigned char, 16> underlying()const noexcept
            {
                std::array<unsigned char, 16> ret{};
                std::copy(addr, addr + 16, ret.begin());
                return ret;
            }

            friend constexpr std::to_chars_result to_chars(char* first, char* last, ipv6_address_t value)noexcept;
            friend constexpr std::from_chars_result from_chars(const char* first, const char* last, ipv6_address_t& value)noexcept;

            friend std::ostream& operator<<(std::ostream& os, ipv6_address_t ip)
            {
                char buf[64]{};
                auto [ptr, ec] = to_chars(buf, buf + 64, ip);
                return os << buf;
            }

            friend std::istream& operator>>(std::istream& is, ipv6_address_t& ip)
            {
                std::string s;
                is >> s;
                if (is)
                {
                    auto [ptr, ec] = from_chars(s.data(), s.data() + s.size(), ip);
                    if (ec != std::errc{})
                    {
                        is.setstate(std::ios::failbit);
                    }
                }
                return is;
            }
        };

        constexpr mac_address_t make_multicast_mac_addr(ipv6_address_t ip)
        {
            if (!ip.is_multicast())
            {
                throw std::invalid_argument{ "not an IPv6 multicast address" };
            }
            std::array<unsigned char, 16> u = ip.underlying();  // 获取字节数组
            return {
                0x33, 0x33,
                u[12], u[13], u[14], u[15]
            };
        }

        constexpr std::to_chars_result to_chars(char* first, char* last, ipv6_address_t value)noexcept
        {
            constexpr auto hex = std::array{ '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
            std::array<unsigned char, 16> u = value.underlying();
            uint_least16_t groups[8]{};
            for (int i = 0; i < 8; ++i)
            {
                groups[i] = ((uint_least16_t)u[i * 2] << 8) | u[i * 2 + 1];
            }
            int best_start = -1, best_len = 0;
            int cur_start = -1;
            for (int i = 0; i < 8; ++i)
            {
                if (groups[i] == 0)
                {
                    if (cur_start == -1) cur_start = i;
                }
                else
                {
                    if (cur_start != -1)
                    {
                        int len = i - cur_start;
                        if (len > best_len) { best_start = cur_start; best_len = len; }
                        cur_start = -1;
                    }
                }
            }
            if (cur_start != -1)
            {
                int len = 8 - cur_start;
                if (len > best_len) { best_start = cur_start; best_len = len; }
            }
            if (best_len <= 1) { best_start = -1; best_len = 0; }

            char buf[40]{};
            char* out = buf;
            for (int i = 0; i < 8; ++i)
            {
                if (best_start != -1 && i == best_start)
                {
                    *out++ = ':';
                    *out++ = ':';
                    i += best_len - 1;
                    continue;
                }
                if (i > 0 && !(best_start != -1 && i == best_start + best_len))
                {
                    *out++ = ':';
                }
                uint_least16_t g = groups[i];
                if (g >= 0x1000) *out++ = hex[g >> 12];
                if (g >= 0x0100) *out++ = hex[(g >> 8) & 0xf];
                if (g >= 0x0010) *out++ = hex[(g >> 4) & 0xf];
                *out++ = hex[g & 0xf];
            }
            if (last - first < out - buf)
            {
                return { last, std::errc::result_out_of_range };
            }
            return { std::copy(buf, out, first), {} };
        }

        constexpr std::from_chars_result from_chars(const char* first, const char* last, ipv6_address_t& value)noexcept
        {
            if (first == last)
            {
                return { first, std::errc::invalid_argument };
            }
            constexpr auto hex_low = std::array{ '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
            constexpr auto hex_upp = std::array{ '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
            auto digit = [](char c) -> int
            {
                for (size_t k = 0; k < 16; ++k)
                {
                    if (hex_low[k] == c || hex_upp[k] == c) return (int)k;
                }
                return -1;
            };
            uint_least16_t groups[8]{};
            int group_count = 0;
            int compress_at = -1;
            const char* p = first;

            if (p < last && *p == ':')
            {
                ++p;
                if (p >= last || *p != ':')
                {
                    return { first, std::errc::invalid_argument };
                }
                ++p;
                compress_at = 0;
                if (p >= last)
                {
                    goto done;
                }
            }

            for (;;)
            {
                if (group_count >= 8)
                {
                    return { first, std::errc::invalid_argument };
                }
                int d = digit(*p);
                if (d < 0)
                {
                    return { first, std::errc::invalid_argument };
                }
                int hex_digits = 1;
                while (hex_digits < 4 && p + 1 < last && digit(p[1]) >= 0)
                {
                    d = (d << 4) | digit(*++p);
                    ++hex_digits;
                }
                groups[group_count++] = (uint_least16_t)d;
                ++p;
                if (p >= last)
                {
                    break;
                }
                if (*p != ':')
                {
                    break;
                }
                ++p;
                if (p < last && *p == ':')
                {
                    if (compress_at != -1)
                    {
                        return { first, std::errc::invalid_argument };
                    }
                    compress_at = group_count;
                    ++p;
                    if (p >= last)
                    {
                        break;
                    }
                }
            }

        done:
            if (compress_at == -1 && group_count != 8)
            {
                return { first, std::errc::invalid_argument };
            }

            unsigned char addr[16]{};
            int zero_count = compress_at != -1 ? 8 - group_count : 0;
            int dst = 0;
            for (int i = 0; i < group_count; ++i)
            {
                if (compress_at == i)
                {
                    for (int j = 0; j < zero_count; ++j)
                    {
                        addr[dst * 2] = 0;
                        addr[dst * 2 + 1] = 0;
                        ++dst;
                    }
                }
                addr[dst * 2] = (unsigned char)(groups[i] >> 8);
                addr[dst * 2 + 1] = (unsigned char)(groups[i] & 0xff);
                ++dst;
            }
            if (compress_at == group_count)
            {
                for (int j = 0; j < zero_count; ++j)
                {
                    addr[dst * 2] = 0;
                    addr[dst * 2 + 1] = 0;
                    ++dst;
                }
            }

            value = ipv6_address_t{ addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15] };
            return { p, {} };
        }
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::ipv4_address_t& ip)noexcept
    {
        if (last - first < 4)
        {
            return { first, std::errc::invalid_argument };
        }
        ip = net::ipv4_address_t{ (unsigned char)first[0], (unsigned char)first[1], (unsigned char)first[2], (unsigned char)first[3] };
        return { first + 4, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::ipv4_address_t ip)noexcept
    {
        if (last - first < 4)
        {
            return { first, std::errc::value_too_large };
        }
        std::array<unsigned char, 4> bt = ip.underlying();
        return { std::transform(bt.begin(), bt.end(), first, [](unsigned char b) { return std::byte{b}; }), {} };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::mac_address_t& mac)noexcept
    {
        if (last - first < 6)
        {
            return { first, std::errc::invalid_argument };
        }
        mac = net::mac_address_t{ (unsigned char)first[0], (unsigned char)first[1], (unsigned char)first[2],
            (unsigned char)first[3], (unsigned char)first[4], (unsigned char)first[5] };
        return { first + 6, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::mac_address_t mac)noexcept
    {
        if (last - first < 6)
        {
            return { first, std::errc::value_too_large };
        }
        std::array<unsigned char, 6> bt = mac.underlying();
        return { std::transform(bt.begin(), bt.end(), first, [](unsigned char b) { return std::byte{b}; }), {} };
    }

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::ipv6_address_t& ip)noexcept
    {
        if (last - first < 16)
        {
            return { first, std::errc::invalid_argument };
        }
        ip = net::ipv6_address_t{ (unsigned char)first[0], (unsigned char)first[1], (unsigned char)first[2],
            (unsigned char)first[3], (unsigned char)first[4], (unsigned char)first[5], (unsigned char)first[6],
            (unsigned char)first[7], (unsigned char)first[8], (unsigned char)first[9], (unsigned char)first[10],
            (unsigned char)first[11], (unsigned char)first[12], (unsigned char)first[13], (unsigned char)first[14],
            (unsigned char)first[15] };
        return { first + 16, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::ipv6_address_t ip)noexcept
    {
        if (last - first < 16)
        {
            return { first, std::errc::value_too_large };
        }
        std::array<unsigned char, 16> bt = ip.underlying();
        return { std::transform(bt.begin(), bt.end(), first, [](unsigned char b) { return std::byte{b}; }), {} };
    }

    inline namespace literals
    {
        inline namespace net_literals
        {
            consteval net::mac_address_t operator""_mac(const char* c, size_t sz)noexcept
            {
                return { std::string_view{c, sz} };
            }

            consteval net::ipv4_address_t operator""_ip(const char* c, size_t sz)noexcept
            {
                return { std::string_view{c, sz} };
            }

            consteval net::ipv6_address_t operator""_ipv6(const char* c, size_t sz)noexcept
            {
                return { std::string_view{c, sz} };
            }

            consteval net::port_t operator""_port(unsigned long long p)noexcept
            {
                if (p > 65535)
                {
                    throw p;
                }
                return (net::port_t)p;
            }
        }
    }
}

template<>
struct std::formatter<Yc::net::ipv4_address_t, char>
{
    template<class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx)
    {
        auto it = ctx.begin();
        auto ed = ctx.end();
        if (it == ed || *it == '}')
        {
            return it;
        }
        throw std::format_error("");
    }

    template<class FmtContext>
    constexpr FmtContext::iterator format(Yc::net::ipv4_address_t ip, FmtContext& ctx) const
    {
        char buffer[16]{};
        char* tmp = buffer;
        char* const end = buffer + 16;
        auto [a, b, c, d] = ip.underlying();
        tmp = std::to_chars(tmp, end, a).ptr;
        *tmp = '.';
        ++tmp;
        tmp = std::to_chars(tmp, end, b).ptr;
        *tmp = '.';
        ++tmp;
        tmp = std::to_chars(tmp, end, c).ptr;
        *tmp = '.';
        ++tmp;
        tmp = std::to_chars(tmp, end, d).ptr;
        return std::copy(buffer, tmp, ctx.out());
    }
};

template<>
struct std::formatter<Yc::net::mac_address_t, char>
{
private:
    char m_hex_case = 'x';
    char m_sep = '-';
    int m_group_size = 2;

public:
    template<class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx)
    {
        auto it = ctx.begin();
        auto ed = ctx.end();
        if (it == ed || *it == '}')
        {
            return it;
        }

        m_hex_case = 0;
        m_sep = 0;
        m_group_size = 0;
        int total_digits = 0;

        while (it != ed && *it != '}')
        {
            int group_len = 0;
            while (it != ed && *it != '}' && (*it == 'x' || *it == 'X'))
            {
                if (m_hex_case == 0)
                {
                    m_hex_case = *it;
                }
                else if (m_hex_case != *it)
                {
                    throw std::format_error("");
                }
                ++group_len;
                ++it;
            }

            if (group_len == 0)
            {
                throw std::format_error("");
            }

            if (m_group_size == 0)
            {
                m_group_size = group_len;
            }
            else if (m_group_size != group_len)
            {
                throw std::format_error("");
            }

            total_digits += group_len;

            if (it != ed && *it != '}')
            {
                if (*it != '-' && *it != ':' && *it != '.')
                {
                    throw std::format_error("");
                }
                if (m_sep == 0)
                {
                    m_sep = *it;
                }
                else if (m_sep != *it)
                {
                    throw std::format_error("");
                }
                ++it;
            }
        }

        if (total_digits != 12)
        {
            throw std::format_error("");
        }

        if (m_sep != 0 && m_group_size != 2 && m_group_size != 4)
        {
            throw std::format_error("");
        }

        return it;
    }

    template<class FmtContext>
    constexpr FmtContext::iterator format(Yc::net::mac_address_t mac, FmtContext& ctx) const
    {
        constexpr auto hex_low = std::array{ '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
        constexpr auto hex_upp = std::array{ '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
        const auto& hex = (m_hex_case == 'X') ? hex_upp : hex_low;

        std::array<unsigned char, 6> u = mac.underlying();
        char buf[18]{};
        char* out = buf;
        for (int i = 0; i < 6; ++i)
        {
            *out++ = hex[u[i] >> 4];
            *out++ = hex[u[i] & 0xf];
            if (i < 5 && m_sep != 0 && (i + 1) * 2 % m_group_size == 0)
            {
                *out++ = m_sep;
            }
        }
        return std::copy(buf, out, ctx.out());
    }
};

template<>
struct std::formatter<Yc::net::ipv6_address_t, char>
{
    template<class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx)
    {
        auto it = ctx.begin();
        auto ed = ctx.end();
        if (it == ed || *it == '}')
        {
            return it;
        }
        throw std::format_error("");
    }

    template<class FmtContext>
    constexpr FmtContext::iterator format(Yc::net::ipv6_address_t ip, FmtContext& ctx) const
    {
        char buffer[64]{};
        char* first = Yc::net::to_chars(buffer, buffer + 64, ip).ptr;
        return std::copy(buffer, first, ctx.out());
    }
};

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

        struct ethernet_header
        {
            mac_address_t dest;
            mac_address_t source;
            uint_least16_t ether_type{};
        };

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

        struct udp_info
        {
            port_t source_port{};
            port_t dest_port{};
            uint_least16_t length{};
            uint_least16_t checksum{};
        };

        struct icmp_echo
        {
            enum type_t : unsigned char
            {
                echo_reply = 0,
                destination_unreachable = 3,
                echo_request = 8,
                time_exceeded = 11,
            };
            type_t type{};
            unsigned char code{};
            uint_least16_t checksum{};
            uint_least16_t identifier{};
            uint_least16_t sequence{};
        };

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

        struct vlan_tag
        {
            uint_least16_t tpid = 0x8100;
            unsigned char pcp{};
            bool dei{};
            uint_least16_t vid{};
        };

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

    constexpr from_bytes_result from_bytes(const std::byte* first, const std::byte* last, net::icmp_echo& icmp)noexcept
    {
        if (last - first < 8)
        {
            return { first, std::errc::invalid_argument };
        }
        icmp.type = (net::icmp_echo::type_t)(unsigned char)first[0];
        icmp.code = (unsigned char)first[1];
        icmp.checksum = (uint_least16_t)first[2] * 256 + (uint_least16_t)first[3];
        icmp.identifier = (uint_least16_t)first[4] * 256 + (uint_least16_t)first[5];
        icmp.sequence = (uint_least16_t)first[6] * 256 + (uint_least16_t)first[7];
        return { first + 8, {} };
    }

    constexpr to_bytes_result to_bytes(std::byte* first, std::byte* last, net::icmp_echo icmp)noexcept
    {
        if (last - first < 8)
        {
            return { first, std::errc::value_too_large };
        }
        first[0] = (std::byte)(icmp.type);
        first[1] = (std::byte)(icmp.code);
        to_bytes(first + 2, last, uint16_bytes(0));
        to_bytes(first + 4, last, uint16_bytes(icmp.identifier));
        to_bytes(first + 6, last, uint16_bytes(icmp.sequence));
        return { first + 8, {} };
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