/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedHomeDevice.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


namespace BPrivate::EncryptedHome::Kernel {

static Device sDevices[kMaxDevices];
static mutex sRegistrationLock;


static bool
RequiredBackingBytes(uint32 sectorSize, uint64 payloadSizeSectors,
	uint64& bytes)
{
	if (payloadSizeSectors > UINT64_MAX - kPayloadOffsetSectors)
		return false;
	const uint64 totalSectors = payloadSizeSectors + kPayloadOffsetSectors;
	if (totalSectors > UINT64_MAX / sectorSize)
		return false;
	bytes = totalSectors * sectorSize;
	return true;
}


static bool
IsEncryptedHomeRawPath(const char* path)
{
	const char* rawBase = ENCRYPTED_HOME_RAW_DEVICE_BASE_NAME;
	const size_t rawBaseLength = strlen(rawBase);
	if (strncmp(path, rawBase, rawBaseLength) == 0
		&& path[rawBaseLength] == '/')
		return true;

	const char devPrefix[] = "/dev/";
	const size_t devPrefixLength = sizeof(devPrefix) - 1;
	if (strncmp(path, devPrefix, devPrefixLength) == 0) {
		path += devPrefixLength;
		return strncmp(path, rawBase, rawBaseLength) == 0
			&& path[rawBaseLength] == '/';
	}

	return false;
}


static status_t
BackingStoreSize(int fd, const struct stat& stat, uint64& bytes)
{
	if (S_ISREG(stat.st_mode)) {
		if (stat.st_size < 0)
			return B_BAD_VALUE;
		bytes = static_cast<uint64>(stat.st_size);
		return B_OK;
	}

	device_geometry geometry = {};
	if (ioctl(fd, B_GET_GEOMETRY, &geometry, sizeof(geometry)) == 0) {
		uint64 sectors = geometry.cylinder_count;
		if (geometry.head_count != 0
			&& sectors > UINT64_MAX / geometry.head_count)
			return B_BAD_VALUE;
		sectors *= geometry.head_count;
		if (geometry.sectors_per_track != 0
			&& sectors > UINT64_MAX / geometry.sectors_per_track)
			return B_BAD_VALUE;
		sectors *= geometry.sectors_per_track;
		if (geometry.bytes_per_sector != 0
			&& sectors > UINT64_MAX / geometry.bytes_per_sector)
			return B_BAD_VALUE;
		bytes = sectors * geometry.bytes_per_sector;
		return B_OK;
	}

	if (stat.st_size < 0)
		return B_BAD_VALUE;
	bytes = static_cast<uint64>(stat.st_size);
	return B_OK;
}


static bool
MatchesBackingStore(const Device& device, const char* path, dev_t backingDevice,
	ino_t backingNode, bool regularFile)
{
	if (strcmp(device.backingPath, path) == 0)
		return true;
	if (device.backingDevice != backingDevice)
		return false;
	if (regularFile)
		return device.backingNode == backingNode;
	return true;
}


status_t
InitializeDevices()
{
	mutex_init(&sRegistrationLock, "encrypted home registration");
	for (uint32 i = 0; i < kMaxDevices; i++) {
		Device& device = sDevices[i];
		mutex_init(&device.lock, "encrypted home device");
		device.id = static_cast<int32>(i);
		device.backingFD = -1;
		device.backingDevice = -1;
		device.backingNode = 0;
		device.keyArea = -1;
		device.key = NULL;
		device.xts = NULL;
		device.openCount = 0;
		device.registered = false;
		device.unlocked = false;
		snprintf(device.rawPath, sizeof(device.rawPath), "%s/%" B_PRIu32 "/raw",
			ENCRYPTED_HOME_RAW_DEVICE_BASE_NAME, i);
	}
	return B_OK;
}


void
UninitializeDevices()
{
	for (uint32 i = 0; i < kMaxDevices; i++) {
		DeviceLock(sDevices[i]);
		if (sDevices[i].backingFD >= 0) {
			close(sDevices[i].backingFD);
			sDevices[i].backingFD = -1;
		}
		mutex_destroy(&sDevices[i].lock);
	}
	mutex_destroy(&sRegistrationLock);
}


Device*
FindDevice(int32 id)
{
	if (id < 0 || id >= static_cast<int32>(kMaxDevices))
		return NULL;
	return &sDevices[id];
}


Device*
AcquireDeviceByRawPath(const char* path)
{
	for (uint32 i = 0; i < kMaxDevices; i++) {
		Device& device = sDevices[i];
		if (strcmp(path, device.rawPath) != 0)
			continue;

		MutexLocker locker(device.lock);
		if (!device.registered)
			return NULL;
		device.openCount++;
		return &device;
	}
	return NULL;
}


void
ReleaseDevice(Device& device)
{
	MutexLocker locker(device.lock);
	if (device.openCount > 0)
		device.openCount--;
}


status_t
RegisterDevice(encrypted_home_ioctl_register& request)
{
	if (request.sectorSize != 512 && request.sectorSize != 4096)
		return B_BAD_VALUE;
	if (request.payloadSizeSectors == 0)
		return B_BAD_VALUE;
	const size_t pathLength = strnlen(request.backingPath,
		sizeof(request.backingPath));
	if (pathLength == 0 || pathLength == sizeof(request.backingPath))
		return B_BAD_VALUE;
	if (IsEncryptedHomeRawPath(request.backingPath))
		return B_BAD_VALUE;

	int fd = open(request.backingPath, O_RDWR);
	if (fd < 0)
		return errno;

	struct stat stat;
	if (fstat(fd, &stat) != 0) {
		status_t status = errno;
		close(fd);
		return status;
	}
	const bool regularFile = S_ISREG(stat.st_mode);
	const dev_t openedDevice = regularFile ? stat.st_dev : stat.st_rdev;
	const ino_t openedNode = stat.st_ino;
	if (openedDevice != request.backingDevice) {
		close(fd);
		return B_MISMATCHED_VALUES;
	}
	uint64 requiredBytes = 0;
	if (!RequiredBackingBytes(request.sectorSize, request.payloadSizeSectors,
			requiredBytes)) {
		close(fd);
		return B_BAD_VALUE;
	}
	uint64 backingBytes = 0;
	status_t status = BackingStoreSize(fd, stat, backingBytes);
	if (status != B_OK) {
		close(fd);
		return status;
	}
	if (backingBytes < requiredBytes) {
		close(fd);
		return B_BAD_VALUE;
	}

	MutexLocker registrationLocker(sRegistrationLock);
	for (uint32 i = 0; i < kMaxDevices; i++) {
		Device& device = sDevices[i];
		MutexLocker locker(device.lock);
		if (device.registered
			&& MatchesBackingStore(device, request.backingPath, openedDevice,
				openedNode, regularFile)) {
			close(fd);
			return B_BUSY;
		}
	}

	for (uint32 i = 0; i < kMaxDevices; i++) {
		Device& device = sDevices[i];
		MutexLocker locker(device.lock);
		if (device.registered)
			continue;

		device.backingFD = fd;
		device.backingDevice = openedDevice;
		device.backingNode = openedNode;
		device.sectorSize = request.sectorSize;
		device.payloadSizeSectors = request.payloadSizeSectors;
		device.cipherId = 0;
		device.keyLength = 0;
		device.registered = true;
		device.unlocked = false;
		strlcpy(device.backingPath, request.backingPath,
			sizeof(device.backingPath));

		request.id = device.id;
		strlcpy(request.rawPath, device.rawPath, sizeof(request.rawPath));
		return B_OK;
	}

	close(fd);
	return B_NO_MEMORY;
}


status_t
UnregisterDevice(int32 id)
{
	Device* device = FindDevice(id);
	if (device == NULL)
		return B_BAD_VALUE;

	MutexLocker locker(device->lock);
	if (device->openCount != 0)
		return B_BUSY;

	DeviceLock(*device);
	if (device->backingFD >= 0) {
		close(device->backingFD);
		device->backingFD = -1;
	}
	device->registered = false;
	device->backingDevice = -1;
	device->backingNode = 0;
	device->sectorSize = 0;
	device->payloadSizeSectors = 0;
	device->backingPath[0] = '\0';
	return B_OK;
}


status_t
FillDeviceInfo(Device& device, encrypted_home_ioctl_info& info)
{
	MutexLocker locker(device.lock);
	if (!device.registered)
		return B_BAD_VALUE;

	info.id = device.id;
	info.unlocked = device.unlocked;
	info.sectorSize = device.sectorSize;
	info.payloadSizeSectors = device.payloadSizeSectors;
	strlcpy(info.backingPath, device.backingPath, sizeof(info.backingPath));
	return B_OK;
}


} // namespace BPrivate::EncryptedHome::Kernel
