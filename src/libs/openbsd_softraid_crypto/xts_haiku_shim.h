/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef XTS_HAIKU_SHIM_H
#define XTS_HAIKU_SHIM_H


#include <stddef.h>
#include <stdint.h>

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef uint8_t u_int8_t;

#ifdef __cplusplus
extern "C" {
#endif

#include "aes_xts.h"


typedef struct xts_haiku_context {
	struct aes_xts_ctx openbsdContext;
} xts_haiku_context;

int xts_haiku_init(xts_haiku_context* context, const uint8_t* key,
	size_t keyLength);
int xts_haiku_crypt(xts_haiku_context* context, uint64_t sector,
	const uint8_t* dataUnit, uint8_t* data, size_t length, bool encrypt);
void xts_haiku_clear(xts_haiku_context* context);

#ifdef __cplusplus
}
#endif

#endif /* XTS_HAIKU_SHIM_H */
