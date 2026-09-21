#pragma once
#include <concepts>
#include <type_traits>
#include <bit>
#include <limits>
#include <array>
namespace Yc
{
	namespace net
	{
		template<std::integral I>
		constexpr I host_to_net(I para)noexcept
		{
			static_assert(std::numeric_limits<unsigned char>::digits == 8);
			static_assert(std::has_unique_object_representations_v<I>);
			if constexpr (std::endian::native == std::endian::big)
			{
				return para;
			}
			else if constexpr(std::endian::native == std::endian::little)
			{
				return std::byteswap(para);
			}
			else
			{
				using U = std::make_signed_t<I>;
				U upara = static_cast<U>(para);
				std::array<unsigned char, sizeof(U)>ret{};
				for (auto it = ret.rbegin(); it != ret.rend(); ++it)
				{
					*it = upara & std::numeric_limits<unsigned char>::max();
					upara >>= std::numeric_limits<unsigned char>::digits;
				}
				return std::bit_cast<I>(ret);
			}
		}

		template<std::integral I>
		constexpr I net_to_host(I para)noexcept
		{
			static_assert(std::numeric_limits<unsigned char>::digits == 8);
			static_assert(std::has_unique_object_representations_v<I>);
			if constexpr (std::endian::native == std::endian::big)
			{
				return para;
			}
			else if constexpr (std::endian::native == std::endian::little)
			{
				return std::byteswap(para);
			}
			else
			{
				using U = std::make_signed_t<I>;
				std::array<unsigned char, sizeof(U)>inner = std::bit_cast<std::array<unsigned char, sizeof(U)>>(para);
				U ret{};
				for (auto uc : inner)
				{
					ret |= uc;
					ret <<= std::numeric_limits<unsigned char>::digits;
				}
				return static_cast<I>(ret);
			}
		}
	}
}