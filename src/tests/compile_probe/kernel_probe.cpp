/*
 * Copyright 2026, Haiku, Inc. All rights reserved.
 * Distributed under the terms of the MIT License.
 */

#include <module.h>


#if __has_include(<array>)
#	include <array>
#endif

#if __has_include(<bit>)
#	include <bit>
#endif

#if __has_include(<expected>)
#	include <expected>
#endif

#if __has_include(<span>)
#	include <span>
#endif


#if __cplusplus < 201703L
#	error "kernel C++ mode must be at least C++17"
#endif


namespace {

enum class ProbeState : int {
	kReady = 7
};


constexpr int
DoubleValue(int value)
{
	return value * 2;
}


[[nodiscard]] status_t
ProbeStatus(ProbeState state)
{
	return state == ProbeState::kReady ? B_OK : B_NOT_ALLOWED;
}


class ProbeGuard {
public:
	ProbeGuard()
		:
		fValue(DoubleValue(3))
	{
	}

	~ProbeGuard()
	{
		fValue = 0;
	}

	int
	Value() const
	{
		return fValue;
	}

private:
	int fValue;
};


status_t
ProbeStdOps(int32 op, ...)
{
	ProbeGuard guard;
	if (guard.Value() != 6)
		return B_BAD_VALUE;

	switch (op) {
		case B_MODULE_INIT:
		case B_MODULE_UNINIT:
			return ProbeStatus(ProbeState::kReady);
		default:
			return B_BAD_VALUE;
	}
}


module_info sKernelProbeModule = {
	"tests/compile_probe/kernel_probe/v1",
	0,
	ProbeStdOps
};

} // namespace


const module_info* modules[] = {
	&sKernelProbeModule,
	NULL
};
