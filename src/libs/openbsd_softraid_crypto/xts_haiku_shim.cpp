/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "xts_haiku_shim.h"

#include <string.h>


namespace {

constexpr size_t kXtsBlockSize = 16;
constexpr size_t kXtsSectorBytes = 8;
constexpr size_t kXtsTweakBytes = 16;


void
EncodeLittleEndian64(uint64_t value, uint8_t* out)
{
	for (size_t i = 0; i < kXtsSectorBytes; i++) {
		out[i] = static_cast<uint8_t>(value & 0xff);
		value >>= 8;
	}
}


void
InitTweak(xts_haiku_context* context, uint64_t sector, const uint8_t* dataUnit)
{
	uint8_t tweak[kXtsTweakBytes];

	if (dataUnit != nullptr) {
		memcpy(tweak, dataUnit, sizeof(tweak));
	} else {
		EncodeLittleEndian64(sector, tweak);
		memset(tweak + kXtsSectorBytes, 0, kXtsTweakBytes - kXtsSectorBytes);
	}

	rijndael_encrypt(&context->openbsdContext.key2, tweak,
		context->openbsdContext.tweak);
}

} // namespace


int
xts_haiku_init(xts_haiku_context* context, const uint8_t* key,
	size_t keyLength)
{
	if (context == nullptr || key == nullptr)
		return -1;
	if (keyLength != 32 && keyLength != 64)
		return -1;

	return aes_xts_setkey(&context->openbsdContext,
		const_cast<uint8_t*>(key), static_cast<int>(keyLength));
}


int
xts_haiku_crypt(xts_haiku_context* context, uint64_t sector,
	const uint8_t* dataUnit, uint8_t* data, size_t length, bool encrypt)
{
	if (context == nullptr || data == nullptr)
		return -1;
	if (length == 0 || (length % kXtsBlockSize) != 0)
		return -1;

	InitTweak(context, sector, dataUnit);

	for (size_t offset = 0; offset < length; offset += kXtsBlockSize) {
		if (encrypt)
			aes_xts_encrypt(&context->openbsdContext, data + offset);
		else
			aes_xts_decrypt(&context->openbsdContext, data + offset);
	}

	return 0;
}


void
xts_haiku_clear(xts_haiku_context* context)
{
	if (context != nullptr)
		aes_xts_zerokey(&context->openbsdContext);
}
