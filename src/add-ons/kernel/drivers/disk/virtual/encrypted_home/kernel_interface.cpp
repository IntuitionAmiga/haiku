/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedHomeDevice.h"

#include <string.h>


using namespace BPrivate::EncryptedHome::Kernel;


int32 api_version = B_CUR_DRIVER_API_VERSION;

static const char* sDeviceNames[kMaxDevices + 2];


static status_t
encrypted_home_open(const char* name, uint32, void** cookie)
{
	if (strcmp(name, ENCRYPTED_HOME_CONTROL_DEVICE_NAME) == 0) {
		*cookie = NULL;
		return B_OK;
	}

	Device* device = AcquireDeviceByRawPath(name);
	if (device == NULL)
		return B_ENTRY_NOT_FOUND;
	*cookie = device;
	return B_OK;
}


static status_t
encrypted_home_close(void*)
{
	return B_OK;
}


static status_t
encrypted_home_free(void* cookie)
{
	if (cookie != NULL)
		ReleaseDevice(*static_cast<Device*>(cookie));
	return B_OK;
}


static status_t
encrypted_home_control(void* cookie, uint32 op, void* buffer, size_t length)
{
	if (cookie == NULL) {
		switch (op) {
			case IOCTL_ENCRYPTED_HOME_REGISTER:
			{
				if (buffer == NULL
					|| length != sizeof(encrypted_home_ioctl_register))
					return B_BAD_VALUE;
				encrypted_home_ioctl_register request = {};
				status_t status = user_memcpy(&request, buffer, sizeof(request));
				if (status != B_OK)
					return status;
				status = RegisterDevice(request);
				if (status != B_OK)
					return status;
				return user_memcpy(buffer, &request, sizeof(request));
			}

			case IOCTL_ENCRYPTED_HOME_UNREGISTER:
			{
				if (buffer == NULL
					|| length != sizeof(encrypted_home_ioctl_unregister))
					return B_BAD_VALUE;
				encrypted_home_ioctl_unregister request = {};
				status_t status = user_memcpy(&request, buffer, sizeof(request));
				if (status != B_OK)
					return status;
				return UnregisterDevice(request.id);
			}

			default:
				return B_DEV_INVALID_IOCTL;
		}
	}

	return DeviceControl(*static_cast<Device*>(cookie), op, buffer, length);
}


static status_t
encrypted_home_read(void* cookie, off_t position, void* buffer,
	size_t* numBytes)
{
	if (cookie == NULL)
		return B_BAD_VALUE;
	return DeviceRead(*static_cast<Device*>(cookie), position, buffer, numBytes);
}


static status_t
encrypted_home_write(void* cookie, off_t position, const void* buffer,
	size_t* numBytes)
{
	if (cookie == NULL)
		return B_BAD_VALUE;
	return DeviceWrite(*static_cast<Device*>(cookie), position, buffer,
		numBytes);
}


static device_hooks sDeviceHooks = {
	encrypted_home_open,
	encrypted_home_close,
	encrypted_home_free,
	encrypted_home_control,
	encrypted_home_read,
	encrypted_home_write,
	NULL,
	NULL,
	NULL,
	NULL
};


extern "C" status_t
init_hardware()
{
	return B_OK;
}


extern "C" status_t
init_driver()
{
	status_t status = InitializeDevices();
	if (status != B_OK)
		return status;

	sDeviceNames[0] = ENCRYPTED_HOME_CONTROL_DEVICE_NAME;
	for (uint32 i = 0; i < kMaxDevices; i++) {
		Device* device = FindDevice(static_cast<int32>(i));
		sDeviceNames[i + 1] = device->rawPath;
	}
	sDeviceNames[kMaxDevices + 1] = NULL;
	return B_OK;
}


extern "C" void
uninit_driver()
{
	UninitializeDevices();
}


extern "C" const char**
publish_devices()
{
	return sDeviceNames;
}


extern "C" device_hooks*
find_device(const char*)
{
	return &sDeviceHooks;
}
