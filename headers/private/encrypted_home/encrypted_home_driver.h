/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef _PRIVATE_ENCRYPTED_HOME_DRIVER_H
#define _PRIVATE_ENCRYPTED_HOME_DRIVER_H


#include <Drivers.h>
#include <StorageDefs.h>


#define ENCRYPTED_HOME_CONTROL_DEVICE_NAME "disk/virtual/encrypted/control"
#define ENCRYPTED_HOME_RAW_DEVICE_BASE_NAME "disk/virtual/encrypted"


enum {
	IOCTL_ENCRYPTED_HOME_REGISTER = B_DEVICE_OP_CODES_END + 2000,
	IOCTL_ENCRYPTED_HOME_UNREGISTER,
	IOCTL_ENCRYPTED_HOME_UNLOCK,
	IOCTL_ENCRYPTED_HOME_LOCK,
	IOCTL_ENCRYPTED_HOME_INFO
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


#endif	// _PRIVATE_ENCRYPTED_HOME_DRIVER_H
