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
#include <functional>
#include <memory>
#include <type_traits>
#include <utility>
#include <variant>
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
                return ((uint_least32_t)ip.addr[0] << 24) | ((uint_least32_t)ip.addr[1] << 16) |
                    ((uint_least32_t)ip.addr[2] << 8) | (uint_least32_t)ip.addr[3];
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
            return { 0x01, 0x00, 0x5e, (unsigned char)(u[1] & 0x7F), u[2], u[3] };
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
                    value = ipv6_address_t{};
                    return { p, {} };
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

        namespace detail
        {
            constexpr std::from_chars_result from_chars_port(const char* first, const char* last, port_t& value)noexcept
            {
                unsigned int port = 0;
                const char* p = first;
                while (p != last && *p >= '0' && *p <= '9')
                {
                    port = port * 10 + (unsigned int)(*p - '0');
                    if (port > 65535)
                    {
                        return { first, std::errc::invalid_argument };
                    }
                    ++p;
                }
                if (p == first)
                {
                    return { first, std::errc::invalid_argument };
                }
                value = (port_t)port;
                return { p, {} };
            }
        }

        // ip 地址和端口号组成的有序对，字符串形式为 "a.b.c.d:port"
        struct ipv4_endpoint
        {
            ipv4_address_t address;
            port_t port{};

            constexpr ipv4_endpoint() = default;
            constexpr ipv4_endpoint(const ipv4_endpoint&) = default;
            constexpr ipv4_endpoint& operator=(const ipv4_endpoint&) = default;
            constexpr ipv4_endpoint(ipv4_address_t addr, port_t port_number)noexcept
                : address(addr), port(port_number)
            {
            }
            constexpr ipv4_endpoint(std::string_view str);

            friend constexpr bool operator==(ipv4_endpoint, ipv4_endpoint) = default;

            friend constexpr auto operator<=>(ipv4_endpoint l, ipv4_endpoint r)noexcept
            {
                if (auto cmp = l.address <=> r.address; cmp != 0)
                {
                    return cmp;
                }
                return (uint_least16_t)l.port <=> (uint_least16_t)r.port;
            }
        };

        // ipv6 地址需要用方括号括起来，字符串形式为 "[ipv6]:port"
        struct ipv6_endpoint
        {
            ipv6_address_t address;
            port_t port{};

            constexpr ipv6_endpoint() = default;
            constexpr ipv6_endpoint(const ipv6_endpoint&) = default;
            constexpr ipv6_endpoint& operator=(const ipv6_endpoint&) = default;
            constexpr ipv6_endpoint(ipv6_address_t addr, port_t port_number)noexcept
                : address(addr), port(port_number)
            {
            }
            constexpr ipv6_endpoint(std::string_view str);

            friend constexpr bool operator==(ipv6_endpoint, ipv6_endpoint) = default;

            friend constexpr auto operator<=>(ipv6_endpoint l, ipv6_endpoint r)noexcept
            {
                if (auto cmp = l.address <=> r.address; cmp != 0)
                {
                    return cmp;
                }
                return (uint_least16_t)l.port <=> (uint_least16_t)r.port;
            }
        };

        constexpr std::from_chars_result from_chars(const char* first, const char* last, ipv4_endpoint& value)noexcept
        {
            ipv4_address_t addr{};
            auto ar = net::from_chars(first, last, addr);
            if (ar.ec != std::errc{})
            {
                return { first, ar.ec };
            }
            if (ar.ptr == last || *ar.ptr != ':')
            {
                return { first, std::errc::invalid_argument };
            }
            port_t port{};
            auto pr = detail::from_chars_port(ar.ptr + 1, last, port);
            if (pr.ec != std::errc{})
            {
                return { first, std::errc::invalid_argument };
            }
            value = ipv4_endpoint{ addr, port };
            return { pr.ptr, {} };
        }

        constexpr std::from_chars_result from_chars(const char* first, const char* last, ipv6_endpoint& value)noexcept
        {
            if (first == last || *first != '[')
            {
                return { first, std::errc::invalid_argument };
            }
            const char* addr_last = std::find(first + 1, last, ']');
            if (addr_last == last)
            {
                return { first, std::errc::invalid_argument };
            }
            ipv6_address_t addr{};
            auto ar = net::from_chars(first + 1, addr_last, addr);
            if (ar.ec != std::errc{} || ar.ptr != addr_last)
            {
                return { first, std::errc::invalid_argument };
            }
            if (addr_last + 1 == last || addr_last[1] != ':')
            {
                return { first, std::errc::invalid_argument };
            }
            port_t port{};
            auto pr = detail::from_chars_port(addr_last + 2, last, port);
            if (pr.ec != std::errc{})
            {
                return { first, std::errc::invalid_argument };
            }
            value = ipv6_endpoint{ addr, port };
            return { pr.ptr, {} };
        }

        constexpr std::to_chars_result to_chars(char* first, char* last, ipv4_endpoint value)noexcept
        {
            char buffer[24]{};
            char* const end = buffer + sizeof(buffer);
            auto [aptr, aec] = net::to_chars(buffer, end, value.address);
            if (aec != std::errc{})
            {
                return { last, std::errc::result_out_of_range };
            }
            *aptr++ = ':';
            auto [pptr, pec] = std::to_chars(aptr, end, (unsigned int)(uint_least16_t)value.port);
            if (pec != std::errc{})
            {
                return { last, std::errc::result_out_of_range };
            }
            if (last - first < pptr - buffer)
            {
                return { last, std::errc::result_out_of_range };
            }
            return { std::copy(buffer, pptr, first), {} };
        }

        constexpr std::to_chars_result to_chars(char* first, char* last, ipv6_endpoint value)noexcept
        {
            char buffer[48]{};
            char* const end = buffer + sizeof(buffer);
            buffer[0] = '[';
            auto [aptr, aec] = net::to_chars(buffer + 1, end - 7, value.address);
            if (aec != std::errc{})
            {
                return { last, std::errc::result_out_of_range };
            }
            *aptr++ = ']';
            *aptr++ = ':';
            auto [pptr, pec] = std::to_chars(aptr, end, (unsigned int)(uint_least16_t)value.port);
            if (pec != std::errc{})
            {
                return { last, std::errc::result_out_of_range };
            }
            if (last - first < pptr - buffer)
            {
                return { last, std::errc::result_out_of_range };
            }
            return { std::copy(buffer, pptr, first), {} };
        }

        constexpr ipv4_endpoint::ipv4_endpoint(std::string_view str)
        {
            auto r = from_chars(str.data(), str.data() + str.size(), *this);
            if (r.ec != std::errc{} || r.ptr != str.data() + str.size())
            {
                throw std::invalid_argument{ "parse ipv4 endpoint str failed!" };
            }
        }

        constexpr ipv6_endpoint::ipv6_endpoint(std::string_view str)
        {
            auto r = from_chars(str.data(), str.data() + str.size(), *this);
            if (r.ec != std::errc{} || r.ptr != str.data() + str.size())
            {
                throw std::invalid_argument{ "parse ipv6 endpoint str failed!" };
            }
        }

        inline std::ostream& operator<<(std::ostream& os, ipv4_endpoint value)
        {
            char buffer[24]{};
            to_chars(buffer, buffer + sizeof(buffer), value);
            return os << buffer;
        }

        inline std::ostream& operator<<(std::ostream& os, ipv6_endpoint value)
        {
            char buffer[48]{};
            to_chars(buffer, buffer + sizeof(buffer), value);
            return os << buffer;
        }

        namespace detail
        {
            template<size_t I>
            struct ip_alternative
            {
                static_assert(I < 2, "ip_address alternative index out of range");
            };

            template<>
            struct ip_alternative<0>
            {
                using type = ipv4_address_t;
            };

            template<>
            struct ip_alternative<1>
            {
                using type = ipv6_address_t;
            };

            struct ip_address_access;
        }

        // 可以存放 IPv4 或 IPv6 地址的联合体，ip_version() 返回 4 或 6
        class ip_address
        {
            union storage_t
            {
                ipv4_address_t v4;
                ipv6_address_t v6;

                constexpr storage_t()noexcept : v4{}
                {
                }
                constexpr storage_t(ipv4_address_t value)noexcept : v4(value)
                {
                }
                constexpr storage_t(ipv6_address_t value)noexcept : v6(value)
                {
                }
            };

            storage_t storage_;
            unsigned char version_;

            friend struct detail::ip_address_access;

        public:
            constexpr ip_address()noexcept : storage_{}, version_(4)
            {
            }
            constexpr ip_address(ipv4_address_t value)noexcept : storage_(value), version_(4)
            {
            }
            constexpr ip_address(ipv6_address_t value)noexcept : storage_(value), version_(6)
            {
            }
            constexpr ip_address(std::string_view str);

            constexpr int ip_version()const noexcept
            {
                return version_;
            }

            // 与 std::variant 一致：IPv4 是 0，IPv6 是 1
            constexpr size_t index()const noexcept
            {
                return is_ipv4() ? 0 : 1;
            }

            constexpr bool is_ipv4()const noexcept
            {
                return version_ == 4;
            }

            constexpr bool is_ipv6()const noexcept
            {
                return version_ == 6;
            }

            constexpr ipv4_address_t as_ipv4()const
            {
                if (!is_ipv4())
                {
                    throw std::invalid_argument{ "not an IPv4 address" };
                }
                return storage_.v4;
            }

            constexpr ipv6_address_t as_ipv6()const
            {
                if (!is_ipv6())
                {
                    throw std::invalid_argument{ "not an IPv6 address" };
                }
                return storage_.v6;
            }

            template<size_t I, class... Args>
            constexpr typename detail::ip_alternative<I>::type& emplace(Args&&... args)
            {
                using alternative = typename detail::ip_alternative<I>::type;
                // 先构造临时对象：构造失败时保持原值不变
                alternative value(std::forward<Args>(args)...);
                if constexpr (I == 0)
                {
                    std::construct_at(&storage_.v4, value);
                    version_ = 4;
                    return storage_.v4;
                }
                else
                {
                    std::construct_at(&storage_.v6, value);
                    version_ = 6;
                    return storage_.v6;
                }
            }

            template<class T, class... Args>
            constexpr T& emplace(Args&&... args)
            {
                static_assert(std::is_same_v<T, ipv4_address_t> || std::is_same_v<T, ipv6_address_t>,
                    "T must be ipv4_address_t or ipv6_address_t");
                if constexpr (std::is_same_v<T, ipv4_address_t>)
                {
                    return emplace<0>(std::forward<Args>(args)...);
                }
                else
                {
                    return emplace<1>(std::forward<Args>(args)...);
                }
            }

            constexpr ip_address& operator=(ipv4_address_t value)noexcept
            {
                *this = ip_address{ value };
                return *this;
            }

            constexpr ip_address& operator=(ipv6_address_t value)noexcept
            {
                *this = ip_address{ value };
                return *this;
            }

            constexpr explicit operator bool()const noexcept
            {
                return is_ipv4() ? (bool)storage_.v4 : (bool)storage_.v6;
            }

            constexpr bool operator==(const ip_address& other)const noexcept
            {
                if (version_ != other.version_)
                {
                    return false;
                }
                return is_ipv4() ? storage_.v4 == other.storage_.v4 : storage_.v6 == other.storage_.v6;
            }

            friend constexpr auto operator<=>(const ip_address& l, const ip_address& r)noexcept
            {
                if (l.version_ != r.version_)
                {
                    return l.version_ <=> r.version_;
                }
                if (l.is_ipv4())
                {
                    return l.storage_.v4 <=> r.storage_.v4;
                }
                return l.storage_.v6 <=> r.storage_.v6;
            }

            template<class Visitor>
            constexpr decltype(auto) visit(Visitor&& vis) &
            {
                if (is_ipv4())
                {
                    return std::invoke(std::forward<Visitor>(vis), storage_.v4);
                }
                return std::invoke(std::forward<Visitor>(vis), storage_.v6);
            }

            template<class Visitor>
            constexpr decltype(auto) visit(Visitor&& vis) const&
            {
                if (is_ipv4())
                {
                    return std::invoke(std::forward<Visitor>(vis), storage_.v4);
                }
                return std::invoke(std::forward<Visitor>(vis), storage_.v6);
            }

            template<class Visitor>
            constexpr decltype(auto) visit(Visitor&& vis) &&
            {
                if (is_ipv4())
                {
                    return std::invoke(std::forward<Visitor>(vis), std::move(storage_.v4));
                }
                return std::invoke(std::forward<Visitor>(vis), std::move(storage_.v6));
            }

            template<class Visitor>
            constexpr decltype(auto) visit(Visitor&& vis) const&&
            {
                if (is_ipv4())
                {
                    return std::invoke(std::forward<Visitor>(vis), std::move(storage_.v4));
                }
                return std::invoke(std::forward<Visitor>(vis), std::move(storage_.v6));
            }
        };

        namespace detail
        {
            struct ip_address_access
            {
                static constexpr ipv4_address_t& v4(ip_address& value)noexcept
                {
                    return value.storage_.v4;
                }

                static constexpr const ipv4_address_t& v4(const ip_address& value)noexcept
                {
                    return value.storage_.v4;
                }

                static constexpr ipv6_address_t& v6(ip_address& value)noexcept
                {
                    return value.storage_.v6;
                }

                static constexpr const ipv6_address_t& v6(const ip_address& value)noexcept
                {
                    return value.storage_.v6;
                }
            };
        }

        template<size_t I>
        constexpr typename detail::ip_alternative<I>::type& get(ip_address& value)
        {
            if (value.index() != I)
            {
                throw std::bad_variant_access{};
            }
            if constexpr (I == 0)
            {
                return detail::ip_address_access::v4(value);
            }
            else
            {
                return detail::ip_address_access::v6(value);
            }
        }

        template<size_t I>
        constexpr const typename detail::ip_alternative<I>::type& get(const ip_address& value)
        {
            if (value.index() != I)
            {
                throw std::bad_variant_access{};
            }
            if constexpr (I == 0)
            {
                return detail::ip_address_access::v4(value);
            }
            else
            {
                return detail::ip_address_access::v6(value);
            }
        }

        template<size_t I>
        constexpr typename detail::ip_alternative<I>::type&& get(ip_address&& value)
        {
            return std::move(get<I>(value));
        }

        template<size_t I>
        constexpr const typename detail::ip_alternative<I>::type&& get(const ip_address&& value)
        {
            return std::move(get<I>(value));
        }

        template<class T>
        constexpr T& get(ip_address& value)
        {
            static_assert(std::is_same_v<T, ipv4_address_t> || std::is_same_v<T, ipv6_address_t>,
                "T must be ipv4_address_t or ipv6_address_t");
            if constexpr (std::is_same_v<T, ipv4_address_t>)
            {
                return get<0>(value);
            }
            else
            {
                return get<1>(value);
            }
        }

        template<class T>
        constexpr const T& get(const ip_address& value)
        {
            static_assert(std::is_same_v<T, ipv4_address_t> || std::is_same_v<T, ipv6_address_t>,
                "T must be ipv4_address_t or ipv6_address_t");
            if constexpr (std::is_same_v<T, ipv4_address_t>)
            {
                return get<0>(value);
            }
            else
            {
                return get<1>(value);
            }
        }

        template<class T>
        constexpr T&& get(ip_address&& value)
        {
            static_assert(std::is_same_v<T, ipv4_address_t> || std::is_same_v<T, ipv6_address_t>,
                "T must be ipv4_address_t or ipv6_address_t");
            if constexpr (std::is_same_v<T, ipv4_address_t>)
            {
                return std::move(get<0>(value));
            }
            else
            {
                return std::move(get<1>(value));
            }
        }

        template<class T>
        constexpr const T&& get(const ip_address&& value)
        {
            static_assert(std::is_same_v<T, ipv4_address_t> || std::is_same_v<T, ipv6_address_t>,
                "T must be ipv4_address_t or ipv6_address_t");
            if constexpr (std::is_same_v<T, ipv4_address_t>)
            {
                return std::move(get<0>(value));
            }
            else
            {
                return std::move(get<1>(value));
            }
        }

        template<size_t I>
        constexpr typename detail::ip_alternative<I>::type* get_if(ip_address* value)noexcept
        {
            if (value == nullptr || value->index() != I)
            {
                return nullptr;
            }
            if constexpr (I == 0)
            {
                return &detail::ip_address_access::v4(*value);
            }
            else
            {
                return &detail::ip_address_access::v6(*value);
            }
        }

        template<size_t I>
        constexpr const typename detail::ip_alternative<I>::type* get_if(const ip_address* value)noexcept
        {
            if (value == nullptr || value->index() != I)
            {
                return nullptr;
            }
            if constexpr (I == 0)
            {
                return &detail::ip_address_access::v4(*value);
            }
            else
            {
                return &detail::ip_address_access::v6(*value);
            }
        }

        template<class T>
        constexpr T* get_if(ip_address* value)noexcept
        {
            static_assert(std::is_same_v<T, ipv4_address_t> || std::is_same_v<T, ipv6_address_t>,
                "T must be ipv4_address_t or ipv6_address_t");
            if constexpr (std::is_same_v<T, ipv4_address_t>)
            {
                return get_if<0>(value);
            }
            else
            {
                return get_if<1>(value);
            }
        }

        template<class T>
        constexpr const T* get_if(const ip_address* value)noexcept
        {
            static_assert(std::is_same_v<T, ipv4_address_t> || std::is_same_v<T, ipv6_address_t>,
                "T must be ipv4_address_t or ipv6_address_t");
            if constexpr (std::is_same_v<T, ipv4_address_t>)
            {
                return get_if<0>(value);
            }
            else
            {
                return get_if<1>(value);
            }
        }

        template<class T>
        constexpr bool holds_alternative(const ip_address& value)noexcept
        {
            static_assert(std::is_same_v<T, ipv4_address_t> || std::is_same_v<T, ipv6_address_t>,
                "T must be ipv4_address_t or ipv6_address_t");
            if constexpr (std::is_same_v<T, ipv4_address_t>)
            {
                return value.is_ipv4();
            }
            else
            {
                return value.is_ipv6();
            }
        }

        // 非成员 visit，ip_address 所在命名空间，可通过 ADL 调用
        template<class Visitor>
        constexpr decltype(auto) visit(Visitor&& vis, ip_address& value)
        {
            return value.visit(std::forward<Visitor>(vis));
        }

        template<class Visitor>
        constexpr decltype(auto) visit(Visitor&& vis, const ip_address& value)
        {
            return value.visit(std::forward<Visitor>(vis));
        }

        template<class Visitor>
        constexpr decltype(auto) visit(Visitor&& vis, ip_address&& value)
        {
            return std::move(value).visit(std::forward<Visitor>(vis));
        }

        template<class Visitor>
        constexpr decltype(auto) visit(Visitor&& vis, const ip_address&& value)
        {
            return std::move(value).visit(std::forward<Visitor>(vis));
        }

        constexpr std::from_chars_result from_chars(const char* first, const char* last, ip_address& value)noexcept
        {
            if (first == last)
            {
                return { first, std::errc::invalid_argument };
            }
            if (*first == '[')
            {
                const char* close = std::find(first + 1, last, ']');
                if (close == last)
                {
                    return { first, std::errc::invalid_argument };
                }
                ipv6_address_t addr{};
                auto r = net::from_chars(first + 1, close, addr);
                if (r.ec != std::errc{} || r.ptr != close)
                {
                    return { first, std::errc::invalid_argument };
                }
                value = ip_address{ addr };
                return { close + 1, {} };
            }
            if (std::find(first, last, ':') != last)
            {
                ipv6_address_t addr{};
                auto r = net::from_chars(first, last, addr);
                if (r.ec != std::errc{})
                {
                    return { first, std::errc::invalid_argument };
                }
                value = ip_address{ addr };
                return { r.ptr, {} };
            }
            ipv4_address_t addr{};
            auto r = net::from_chars(first, last, addr);
            if (r.ec != std::errc{})
            {
                return { first, std::errc::invalid_argument };
            }
            value = ip_address{ addr };
            return { r.ptr, {} };
        }

        constexpr std::to_chars_result to_chars(char* first, char* last, ip_address value)noexcept
        {
            if (value.is_ipv4())
            {
                return net::to_chars(first, last, value.as_ipv4());
            }
            return net::to_chars(first, last, value.as_ipv6());
        }

        constexpr ip_address::ip_address(std::string_view str) : storage_{}, version_(4)
        {
            auto r = from_chars(str.data(), str.data() + str.size(), *this);
            if (r.ec != std::errc{} || r.ptr != str.data() + str.size())
            {
                throw std::invalid_argument{ "parse ip address str failed!" };
            }
        }

        inline std::ostream& operator<<(std::ostream& os, ip_address value)
        {
            char buffer[48]{};
            to_chars(buffer, buffer + sizeof(buffer), value);
            return os << buffer;
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

template<>
struct std::formatter<Yc::net::ipv4_endpoint, char>
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
    constexpr FmtContext::iterator format(Yc::net::ipv4_endpoint ep, FmtContext& ctx) const
    {
        char buffer[24]{};
        char* first = Yc::net::to_chars(buffer, buffer + 24, ep).ptr;
        return std::copy(buffer, first, ctx.out());
    }
};

template<>
struct std::formatter<Yc::net::ipv6_endpoint, char>
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
    constexpr FmtContext::iterator format(Yc::net::ipv6_endpoint ep, FmtContext& ctx) const
    {
        char buffer[48]{};
        char* first = Yc::net::to_chars(buffer, buffer + 48, ep).ptr;
        return std::copy(buffer, first, ctx.out());
    }
};

template<>
struct std::formatter<Yc::net::ip_address, char>
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
    constexpr FmtContext::iterator format(Yc::net::ip_address ip, FmtContext& ctx) const
    {
        char buffer[64]{};
        char* first = Yc::net::to_chars(buffer, buffer + 64, ip).ptr;
        return std::copy(buffer, first, ctx.out());
    }
};

template<>
struct std::variant_size<Yc::net::ip_address> : std::integral_constant<std::size_t, 2>
{
};

template<>
struct std::variant_alternative<0, Yc::net::ip_address>
{
    using type = Yc::net::ipv4_address_t;
};

template<>
struct std::variant_alternative<1, Yc::net::ip_address>
{
    using type = Yc::net::ipv6_address_t;
};

