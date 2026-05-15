/*
 * Copyright 2026, Haiku, Inc. All rights reserved.
 * Distributed under the terms of the MIT License.
 */

#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <type_traits>
#include <version>


#if !defined(__cpp_lib_expected) || __cpp_lib_expected < 202202L
#	error "missing <expected> (need __cpp_lib_expected >= 202202)"
#endif

#if !defined(__cpp_lib_span)
#	error "missing <span>"
#endif

#if !defined(__cpp_lib_byteswap)
#	error "missing std::byteswap"
#endif

#if !defined(__cpp_concepts)
#	error "missing concepts"
#endif


constexpr std::array<std::byte, 3> kBytes {};
constexpr std::span<const std::byte, 3> kSpan {kBytes};
static_assert(kSpan.size() == 3);

constexpr std::expected<int, int> kExpected {42};
static_assert(kExpected.value() == 42);

constexpr auto kSwapped = std::byteswap(std::uint32_t {0x01020304});
static_assert(kSwapped == 0x04030201);

template<typename Type>
concept Trivial = std::is_trivial_v<Type>;
static_assert(Trivial<int>);


int
main()
{
	return 0;
}
