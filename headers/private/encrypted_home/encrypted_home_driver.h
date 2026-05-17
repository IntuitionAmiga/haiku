/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef _PRIVATE_ENCRYPTED_HOME_DRIVER_H
#define _PRIVATE_ENCRYPTED_HOME_DRIVER_H


#include <Drivers.h>
#include <StorageDefs.h>

#include <encrypted_home_driver_layout.h>


#define ENCRYPTED_HOME_CONTROL_DEVICE_NAME "disk/virtual/encrypted/control"
#define ENCRYPTED_HOME_RAW_DEVICE_BASE_NAME "disk/virtual/encrypted"


enum {
	IOCTL_ENCRYPTED_HOME_REGISTER
		= BPrivate::EncryptedHome::driver_wire::kIoctlRegister,
	IOCTL_ENCRYPTED_HOME_UNREGISTER
		= BPrivate::EncryptedHome::driver_wire::kIoctlUnregister,
	IOCTL_ENCRYPTED_HOME_UNLOCK
		= BPrivate::EncryptedHome::driver_wire::kIoctlUnlock,
	IOCTL_ENCRYPTED_HOME_LOCK
		= BPrivate::EncryptedHome::driver_wire::kIoctlLock,
	IOCTL_ENCRYPTED_HOME_INFO
		= BPrivate::EncryptedHome::driver_wire::kIoctlInfo
};


struct encrypted_home_ioctl_register {
	dev_t backingDevice;
	uint32 sectorSize;
	uint64 payloadSizeSectors;
	char backingPath[B_PATH_NAME_LENGTH];

	int32 id;
	char rawPath[B_PATH_NAME_LENGTH];
};


struct encrypted_home_ioctl_unregister {
	int32 id;
};


struct encrypted_home_ioctl_unlock {
	uint32 cipherId;
	uint32 masterKeyLength;
	uint8 masterKey[64];
};


struct encrypted_home_ioctl_info {
	int32 id;
	bool unlocked;
	uint32 sectorSize;
	uint64 payloadSizeSectors;
	char backingPath[B_PATH_NAME_LENGTH];
};

static_assert(B_DEVICE_OP_CODES_END
	== BPrivate::EncryptedHome::driver_wire::kDeviceOpCodesEnd);
static_assert(B_PATH_NAME_LENGTH
	== BPrivate::EncryptedHome::driver_wire::kPathNameLength);

static_assert(sizeof(encrypted_home_ioctl_register)
	== BPrivate::EncryptedHome::driver_wire::kRegisterSize);
static_assert(offsetof(encrypted_home_ioctl_register, backingDevice)
	== BPrivate::EncryptedHome::driver_wire::kRegisterFields[0].offset);
static_assert(offsetof(encrypted_home_ioctl_register, sectorSize)
	== BPrivate::EncryptedHome::driver_wire::kRegisterFields[1].offset);
static_assert(offsetof(encrypted_home_ioctl_register, payloadSizeSectors)
	== BPrivate::EncryptedHome::driver_wire::kRegisterFields[2].offset);
static_assert(offsetof(encrypted_home_ioctl_register, backingPath)
	== BPrivate::EncryptedHome::driver_wire::kRegisterFields[3].offset);
static_assert(offsetof(encrypted_home_ioctl_register, id)
	== BPrivate::EncryptedHome::driver_wire::kRegisterFields[4].offset);
static_assert(offsetof(encrypted_home_ioctl_register, rawPath)
	== BPrivate::EncryptedHome::driver_wire::kRegisterFields[5].offset);

static_assert(sizeof(encrypted_home_ioctl_unregister)
	== BPrivate::EncryptedHome::driver_wire::kUnregisterSize);
static_assert(offsetof(encrypted_home_ioctl_unregister, id)
	== BPrivate::EncryptedHome::driver_wire::kUnregisterFields[0].offset);

static_assert(sizeof(encrypted_home_ioctl_unlock)
	== BPrivate::EncryptedHome::driver_wire::kUnlockSize);
static_assert(offsetof(encrypted_home_ioctl_unlock, cipherId)
	== BPrivate::EncryptedHome::driver_wire::kUnlockFields[0].offset);
static_assert(offsetof(encrypted_home_ioctl_unlock, masterKeyLength)
	== BPrivate::EncryptedHome::driver_wire::kUnlockFields[1].offset);
static_assert(offsetof(encrypted_home_ioctl_unlock, masterKey)
	== BPrivate::EncryptedHome::driver_wire::kUnlockFields[2].offset);

static_assert(sizeof(encrypted_home_ioctl_info)
	== BPrivate::EncryptedHome::driver_wire::kInfoSize);
static_assert(offsetof(encrypted_home_ioctl_info, id)
	== BPrivate::EncryptedHome::driver_wire::kInfoFields[0].offset);
static_assert(offsetof(encrypted_home_ioctl_info, unlocked)
	== BPrivate::EncryptedHome::driver_wire::kInfoFields[1].offset);
static_assert(offsetof(encrypted_home_ioctl_info, sectorSize)
	== BPrivate::EncryptedHome::driver_wire::kInfoFields[2].offset);
static_assert(offsetof(encrypted_home_ioctl_info, payloadSizeSectors)
	== BPrivate::EncryptedHome::driver_wire::kInfoFields[3].offset);
static_assert(offsetof(encrypted_home_ioctl_info, backingPath)
	== BPrivate::EncryptedHome::driver_wire::kInfoFields[4].offset);


#endif	// _PRIVATE_ENCRYPTED_HOME_DRIVER_H
