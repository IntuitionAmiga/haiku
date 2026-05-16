/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef ENCRYPTED_HOME_DEVICE_H
#define ENCRYPTED_HOME_DEVICE_H


#include <encrypted_home_driver.h>

#include <Drivers.h>
#include <KernelExport.h>
#include <OS.h>
#include <lock.h>
#include <util/AutoLock.h>

#include <stddef.h>
#include <stdint.h>


struct xts_haiku_context;


namespace BPrivate::EncryptedHome::Kernel {

static const uint32 kPayloadOffsetSectors = 16;
static const uint32 kMaxDevices = 8;
static const uint32 kCipherAES128XTS = 1;
static const uint32 kCipherAES256XTS = 2;


struct Device {
	mutex lock;
	int32 id;
	int backingFD;
	dev_t backingDevice;
	ino_t backingNode;
	area_id keyArea;
	uint8* key;
	uint32 keyLength;
	uint32 cipherId;
	uint32 sectorSize;
	uint64 payloadSizeSectors;
	uint32 openCount;
	bool registered;
	bool unlocked;
	char backingPath[B_PATH_NAME_LENGTH];
	char rawPath[B_PATH_NAME_LENGTH];
	xts_haiku_context* xts;
};


status_t InitializeDevices();
void UninitializeDevices();
Device* FindDevice(int32 id);
Device* AcquireDeviceByRawPath(const char* path);
void ReleaseDevice(Device& device);
status_t RegisterDevice(encrypted_home_ioctl_register& request);
status_t UnregisterDevice(int32 id);
status_t FillDeviceInfo(Device& device, encrypted_home_ioctl_info& info);

status_t DeviceUnlock(Device& device,
	const encrypted_home_ioctl_unlock& request);
status_t DeviceLock(Device& device);
status_t DeviceRead(Device& device, off_t position, void* buffer,
	size_t* numBytes);
status_t DeviceWrite(Device& device, off_t position, const void* buffer,
	size_t* numBytes);
status_t DeviceControl(Device& device, uint32 op, void* buffer, size_t length);

inline void
SecureZero(void* buffer, size_t length)
{
	volatile uint8* bytes = static_cast<volatile uint8*>(buffer);
	for (size_t i = 0; i < length; i++)
		bytes[i] = 0;
}

} // namespace BPrivate::EncryptedHome::Kernel


#endif	// ENCRYPTED_HOME_DEVICE_H
