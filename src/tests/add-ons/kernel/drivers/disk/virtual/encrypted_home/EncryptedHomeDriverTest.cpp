/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <encrypted_home_driver.h>

#include <Drivers.h>

#include <cstddef>
#include <cstdio>
#include <cstring>


static bool
Assert(bool condition, const char* message)
{
	if (!condition)
		std::fprintf(stderr, "EncryptedHomeDriverTest: %s\n", message);
	return condition;
}


static bool
TestIoctlContract()
{
	encrypted_home_ioctl_register request = {};
	request.backingDevice = 42;
	request.sectorSize = 512;
	request.payloadSizeSectors = 128;
	strlcpy(request.backingPath, "/tmp/backing", sizeof(request.backingPath));

	return Assert(IOCTL_ENCRYPTED_HOME_REGISTER != IOCTL_ENCRYPTED_HOME_UNLOCK,
			"register and unlock ioctls must be distinct")
		&& Assert(sizeof(request.backingPath) == B_PATH_NAME_LENGTH,
			"register request must carry a bounded backing path")
		&& Assert(sizeof(encrypted_home_ioctl_unlock::masterKey) == 64,
			"unlock request must carry the largest XTS master key")
		&& Assert(request.id == 0, "register return id must zero-initialize");
}


static bool
TestDeviceNames()
{
	return Assert(std::strcmp(ENCRYPTED_HOME_CONTROL_DEVICE_NAME,
			"disk/virtual/encrypted/control") == 0,
			"control device name is part of the userland driver contract")
		&& Assert(std::strcmp(ENCRYPTED_HOME_RAW_DEVICE_BASE_NAME,
			"disk/virtual/encrypted") == 0,
			"raw device base name is part of the userland driver contract");
}


static bool
TestRequestLayout()
{
	return Assert(offsetof(encrypted_home_ioctl_register, backingDevice) == 0,
			"register request starts with backingDevice")
		&& Assert(offsetof(encrypted_home_ioctl_register, backingPath)
				> offsetof(encrypted_home_ioctl_register, payloadSizeSectors),
			"register request carries geometry before backing path")
		&& Assert(offsetof(encrypted_home_ioctl_register, id)
				> offsetof(encrypted_home_ioctl_register, backingPath),
			"register response id follows bounded input path")
		&& Assert(offsetof(encrypted_home_ioctl_unlock, masterKey)
				> offsetof(encrypted_home_ioctl_unlock, masterKeyLength),
			"unlock request carries key bytes after key metadata")
		&& Assert(offsetof(encrypted_home_ioctl_info, backingPath)
				> offsetof(encrypted_home_ioctl_info, payloadSizeSectors),
			"info response carries geometry before backing path");
}


int
main()
{
	if (!TestIoctlContract())
		return 1;
	if (!TestDeviceNames())
		return 1;
	if (!TestRequestLayout())
		return 1;
	return 0;
}
