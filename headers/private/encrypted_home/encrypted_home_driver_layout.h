/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef _PRIVATE_ENCRYPTED_HOME_DRIVER_LAYOUT_H
#define _PRIVATE_ENCRYPTED_HOME_DRIVER_LAYOUT_H


#include <stddef.h>


namespace BPrivate::EncryptedHome::driver_wire {

static constexpr unsigned int kDeviceOpCodesEnd = 9999;
static constexpr unsigned int kIoctlRegister = kDeviceOpCodesEnd + 2000;
static constexpr unsigned int kIoctlUnregister = kIoctlRegister + 1;
static constexpr unsigned int kIoctlUnlock = kIoctlRegister + 2;
static constexpr unsigned int kIoctlLock = kIoctlRegister + 3;
static constexpr unsigned int kIoctlInfo = kIoctlRegister + 4;

static constexpr size_t kPathNameLength = 1024;

struct LayoutField {
	const char* name;
	size_t offset;
	size_t size;
	const char* description;
};

static constexpr size_t kRegisterSize = 2072;
static constexpr LayoutField kRegisterFields[] = {
	{"backingDevice", 0, 4,
		"Device id expected for the backing file or block device"},
	{"sectorSize", 4, 4,
		"Backing logical sector size; supported values are 512 and 4096"},
	{"payloadSizeSectors", 8, 8, "Plaintext payload size in sectors"},
	{"backingPath", 16, kPathNameLength,
		"NUL-terminated path to the backing store"},
	{"id", 1040, 4, "Returned encrypted-home device slot id"},
	{"rawPath", 1044, kPathNameLength, "Returned raw virtual device path"},
};

static constexpr size_t kUnregisterSize = 4;
static constexpr LayoutField kUnregisterFields[] = {
	{"id", 0, 4, "Encrypted-home device slot id to unregister"},
};

static constexpr size_t kUnlockSize = 72;
static constexpr LayoutField kUnlockFields[] = {
	{"cipherId", 0, 4,
		"Cipher id from the authenticated encrypted-home header"},
	{"masterKeyLength", 4, 4,
		"Length of masterKey in bytes; 32 for AES-128-XTS, 64 for AES-256-XTS"},
	{"masterKey", 8, 64, "Unwrapped XTS master key bytes; unused tail must be zero"},
};

static constexpr size_t kInfoSize = 1048;
static constexpr LayoutField kInfoFields[] = {
	{"id", 0, 4, "Encrypted-home device slot id"},
	{"unlocked", 4, 1, "Whether the raw node currently has an active XTS key"},
	{"sectorSize", 8, 4, "Backing logical sector size"},
	{"payloadSizeSectors", 16, 8, "Plaintext payload size in sectors"},
	{"backingPath", 24, kPathNameLength, "Registered backing store path"},
};

} // namespace BPrivate::EncryptedHome::driver_wire


#endif	// _PRIVATE_ENCRYPTED_HOME_DRIVER_LAYOUT_H
