#pragma once
#include <type_traits>
#include <charconv>
#include <system_error>
#include <string_view>
#include <algorithm>
#include <format>
#include <iterator>
#include <istream>
namespace Yc
{
    namespace details
    {
        namespace
        {
            constexpr int isalpha(int c)noexcept
            {
                if (c >= 'a' && c <= 'z')
                {
                    return true;
                }
                if (c >= 'A' && c <= 'Z')
                {
                    return true;
                }
                return false;
            }
        }
    }
    class io_bool
    {
        bool inner{};
    public:
        constexpr io_bool() = default;
        constexpr io_bool(const io_bool&) = default;
        constexpr io_bool& operator=(const io_bool&) = default;
        template<class T>
        constexpr io_bool(T&& para)noexcept(std::is_nothrow_constructible_v<bool, T>) :inner{ std::forward<T>(para) }
        {
        }
        constexpr const char* c_str()const noexcept
        {
            return inner ? "true" : "false";
        }
        constexpr explicit operator std::string_view()const noexcept
        {
            return { c_str() };
        }
        constexpr explicit operator std::wstring_view()const noexcept
        {
            return inner ? L"true" : L"false";
        }
        constexpr operator bool()const noexcept
        {
            return inner;
        }
    };
    constexpr inline io_bool io_true{ true }, io_false{ false };
    constexpr std::to_chars_result to_chars(char* first, char* last, io_bool value)noexcept
    {
        size_t size_needed = value ? 4 : 5;
        if (last - first < size_needed)
        {
            return { last, std::errc::result_out_of_range };
        }
        std::string_view sv{ value };
        std::copy(sv.begin(), sv.end(), first);
        return { first + size_needed, {} };
    }

    constexpr std::from_chars_result from_chars(const char* first, const char* last, io_bool& value)noexcept
    {
        size_t sz = last - first;
        char t[] = "true";
        char f[] = "false";
        if (sz < 4)
        {
            return { first, std::errc::invalid_argument };
        }
        if (sz == 4)
        {

            if (std::equal(first, last, t))
            {
                value = io_true;
                return { last, {} };
            }
            else
            {
                return { first, std::errc::invalid_argument };
            }
        }
        if (sz == 5)
        {
            if (details::isalpha((unsigned char)first[4]))
            {
                if (std::equal(first, last, f))
                {
                    value = io_false;
                    return { last, {} };
                }
                else
                {
                    return { first, std::errc::invalid_argument };
                }
            }
            else
            {
                if (std::equal(first, last - 1, t))
                {
                    value = io_true;
                    return { last - 1, {} };
                }
                else
                {
                    return { first, std::errc::invalid_argument };
                }
            }
        }
        if (details::isalpha((unsigned char)first[4]))
        {
            if (!details::isalpha((unsigned char)first[5]) && std::equal(first, first + 5, f))
            {
                value = io_false;
                return { first + 5, {} };
            }
            else
            {
                return { first, std::errc::invalid_argument };
            }
        }
        else
        {
            if (std::equal(first, first + 4, t))
            {
                value = io_true;
                return { first + 4, {} };
            }
            else
            {
                return { first, std::errc::invalid_argument };
            }
        }
    }

    inline std::ostream& operator<<(std::ostream& os, io_bool value)
    {
        return os << value.c_str();
    }

    inline std::istream& operator>>(std::istream& is, io_bool& value)
    {
        std::istream::sentry sentry(is);
        if (!sentry)
            return is;

        auto sb = is.rdbuf();
        int c = sb->sgetc();
        if (c == std::char_traits<char>::eof())
        {
            is.setstate(std::ios_base::failbit);
            return is;
        }

        if (c == 't')
        {
            sb->sbumpc();
            if (sb->sgetc() != 'r') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            if (sb->sgetc() != 'u') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            if (sb->sgetc() != 'e') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            c = sb->sgetc();
            if (c != std::char_traits<char>::eof() && details::isalpha(static_cast<unsigned char>(c)))
            {
                is.setstate(std::ios_base::failbit);
                return is;
            }
            value = io_true;
        }
        else if (c == 'f')
        {
            sb->sbumpc();
            if (sb->sgetc() != 'a') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            if (sb->sgetc() != 'l') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            if (sb->sgetc() != 's') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            if (sb->sgetc() != 'e') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            c = sb->sgetc();
            if (c != std::char_traits<char>::eof() && details::isalpha(static_cast<unsigned char>(c)))
            {
                is.setstate(std::ios_base::failbit);
                return is;
            }
            value = io_false;
        }
        else
        {
            is.setstate(std::ios_base::failbit);
        }
        return is;
    }

    inline std::wostream& operator<<(std::wostream& os, io_bool value)
    {
        return os << (value ? L"true" : L"false");
    }

    inline std::wistream& operator>>(std::wistream& is, io_bool& value)
    {
        std::wistream::sentry sentry(is);
        if (!sentry)
            return is;

        auto sb = is.rdbuf();
        auto c = sb->sgetc();
        if (c == std::char_traits<wchar_t>::eof())
        {
            is.setstate(std::ios_base::failbit);
            return is;
        }

        if (c == L't')
        {
            sb->sbumpc();
            if (sb->sgetc() != L'r') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            if (sb->sgetc() != L'u') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            if (sb->sgetc() != L'e') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            c = sb->sgetc();
            if (c != std::char_traits<wchar_t>::eof() && details::isalpha(static_cast<unsigned char>(c)))
            {
                is.setstate(std::ios_base::failbit);
                return is;
            }
            value = io_true;
        }
        else if (c == L'f')
        {
            sb->sbumpc();
            if (sb->sgetc() != L'a') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            if (sb->sgetc() != L'l') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            if (sb->sgetc() != L's') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            if (sb->sgetc() != L'e') { is.setstate(std::ios_base::failbit); return is; }
            sb->sbumpc();
            c = sb->sgetc();
            if (c != std::char_traits<wchar_t>::eof() && details::isalpha(static_cast<unsigned char>(c)))
            {
                is.setstate(std::ios_base::failbit);
                return is;
            }
            value = io_false;
        }
        else
        {
            is.setstate(std::ios_base::failbit);
        }
        return is;
    }
}

template<>
struct std::formatter<Yc::io_bool, char>
{
    std::string_view true_name = "true";
    std::string_view false_name = "false";
    size_t true_id = size_t(-1);
    size_t false_id = size_t(-1);

    template<class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx)
    {
        auto it = ctx.begin();
        auto ed = ctx.end();
        if (it == ed || *it == '}')
        {
            return it;
        }

        // parse true name
        if (*it == '{')
        {
            if (*(it + 1) == '}')
            {
                true_id = ctx.next_arg_id();
                it += 2;
            }
            else
            {
                const char* para_id_begin = std::to_address(it) + 1;
                const char* para_id_end = std::to_address(ctx.end());
                std::from_chars_result result = std::from_chars(para_id_begin, para_id_end, true_id);
                if (result.ec != std::errc{} || result.ptr == para_id_end || *result.ptr != '}')
                {
                    throw std::format_error("invalid replacement field");
                }
                it += 2 + (result.ptr - para_id_begin);
                ctx.check_arg_id(true_id);
            }
            if (*it != '|')
            {
                throw std::format_error("separator '|' not found");
            }
        }
        else
        {
            auto ed1 = std::find(it, ed, '}');
            auto it1 = std::find(it, ed1, '|');

            if (it1 == ed1)
            {
                throw std::format_error("separator '|' not found");
            }
            true_name = std::string_view{ it, it1 };
            it = it1;
        }

        ++it;
        // parse false name
        if (*it == '{')
        {
            if (*(it + 1) == '}')
            {
                false_id = ctx.next_arg_id();
                it += 2;
            }
            else
            {
                const char* para_id_begin = std::to_address(it) + 1;
                const char* para_id_end = std::to_address(ctx.end());
                std::from_chars_result result = std::from_chars(para_id_begin, para_id_end, false_id);
                if (result.ec != std::errc{} || result.ptr == para_id_end || *result.ptr != '}')
                {
                    throw std::format_error("invalid replacement field");
                }
                it += 2 + (result.ptr - para_id_begin);
                ctx.check_arg_id(false_id);
            }
            if (*it != '}')
            {
                throw std::format_error("unexpected characters after replacement field");
            }
        }
        else
        {
            auto ed1 = std::find(it, ed, '}');
            if (ed1 == ed)
            {
                throw std::format_error("unmatched '}' in replacement field");
            }
            false_name = std::string_view{ it, ed1 };
            it = ed1;
        }
        return it;
    }

    template<class FmtContext>
    constexpr FmtContext::iterator format(Yc::io_bool b, FmtContext& ctx) const
    {
        std::string_view output{};
        size_t arg_id = -1;
        if (b)
        {
            output = true_name;
            arg_id = true_id;
        }
        else
        {
            output = false_name;
            arg_id = false_id;
        }
        if (arg_id == -1)
        {
            return std::copy(output.begin(), output.end(), ctx.out());
        }
        else
        {
            auto arg_h = ctx.arg(arg_id);
            auto&& formatted = std::visit_format_arg([]<class T>(T a)
            {
                if constexpr (std::is_constructible_v<std::string_view, T>)
                {
                    return std::string{ std::string_view{ a } };
                }
                else
                {
                    std::string buf;
                    std::format_to(std::back_inserter(buf), "{}", a);
                    return buf;
                }
            }, arg_h);
            return std::copy(formatted.begin(), formatted.end(), ctx.out());
        }
    }
};

template<>
struct std::hash<Yc::io_bool>
{
    constexpr size_t operator()(Yc::io_bool b)const noexcept
    {
        return std::hash<bool>{}(static_cast<bool>(b));
    }
};

template<>
struct std::formatter<Yc::io_bool, wchar_t>
{
    std::wstring_view true_name = L"true";
    std::wstring_view false_name = L"false";
    size_t true_id = size_t(-1);
    size_t false_id = size_t(-1);

    template<class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext& ctx)
    {
        auto it = ctx.begin();
        auto ed = ctx.end();
        if (it == ed || *it == L'}')
        {
            return it;
        }

        // parse true name
        if (*it == L'{')
        {
            if (*(it + 1) == L'}')
            {
                true_id = ctx.next_arg_id();
                it += 2;
            }
            else
            {
                const wchar_t* para_id_begin = std::to_address(it) + 1;
                const wchar_t* para_id_end = std::to_address(ctx.end());
                const wchar_t* p = para_id_begin;
                true_id = 0;
                while (p != para_id_end && L'0' <= *p && *p <= L'9')
                {
                    true_id = true_id * 10 + static_cast<size_t>(*p - L'0');
                    ++p;
                }
                if (p == para_id_begin || p == para_id_end || *p != L'}')
                {
                    throw std::format_error("invalid replacement field");
                }
                it += 2 + (p - para_id_begin);
                ctx.check_arg_id(true_id);
            }
            if (*it != L'|')
            {
                throw std::format_error("separator '|' not found");
            }
        }
        else
        {
            auto ed1 = std::find(it, ed, L'}');
            auto it1 = std::find(it, ed1, L'|');

            if (it1 == ed1)
            {
                throw std::format_error("separator '|' not found");
            }
            true_name = std::wstring_view{ it, it1 };
            it = it1;
        }

        ++it;
        // parse false name
        if (*it == L'{')
        {
            if (*(it + 1) == L'}')
            {
                false_id = ctx.next_arg_id();
                it += 2;
            }
            else
            {
                const wchar_t* para_id_begin = std::to_address(it) + 1;
                const wchar_t* para_id_end = std::to_address(ctx.end());
                const wchar_t* p = para_id_begin;
                false_id = 0;
                while (p != para_id_end && L'0' <= *p && *p <= L'9')
                {
                    false_id = false_id * 10 + static_cast<size_t>(*p - L'0');
                    ++p;
                }
                if (p == para_id_begin || p == para_id_end || *p != L'}')
                {
                    throw std::format_error("invalid replacement field");
                }
                it += 2 + (p - para_id_begin);
                ctx.check_arg_id(false_id);
            }
            if (*it != L'}')
            {
                throw std::format_error("unexpected characters after replacement field");
            }
        }
        else
        {
            auto ed1 = std::find(it, ed, L'}');
            if (ed1 == ed)
            {
                throw std::format_error("unmatched '}' in replacement field");
            }
            false_name = std::wstring_view{ it, ed1 };
            it = ed1;
        }
        return it;
    }

    template<class FmtContext>
    constexpr FmtContext::iterator format(Yc::io_bool b, FmtContext& ctx) const
    {
        std::wstring_view output{};
        size_t arg_id = -1;
        if (b)
        {
            output = true_name;
            arg_id = true_id;
        }
        else
        {
            output = false_name;
            arg_id = false_id;
        }
        if (arg_id == -1)
        {
            return std::copy(output.begin(), output.end(), ctx.out());
        }
        else
        {
            auto arg_h = ctx.arg(arg_id);
            auto&& formatted = std::visit_format_arg([]<class T>(T a)
            {
                if constexpr (std::is_constructible_v<std::wstring_view, T>)
                {
                    return std::wstring{ std::wstring_view{ a } };
                }
                else
                {
                    std::wstring buf;
                    std::format_to(std::back_inserter(buf), L"{}", a);
                    return buf;
                }
            }, arg_h);
            return std::copy(formatted.begin(), formatted.end(), ctx.out());
        }
    }
};