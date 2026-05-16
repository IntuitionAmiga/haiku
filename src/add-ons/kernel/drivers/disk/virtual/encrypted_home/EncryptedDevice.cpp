/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedHomeDevice.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xts_haiku_shim.h"


namespace BPrivate::EncryptedHome::Kernel {

static constexpr size_t kMaxRawIOTransferBytes = 64 * 1024;


static uint64
PayloadBytes(const Device& device)
{
	if (device.payloadSizeSectors > UINT64_MAX / device.sectorSize)
		return 0;
	return device.payloadSizeSectors * device.sectorSize;
}


static status_t
BackingOffsetForPayload(const Device& device, off_t position, uint64& offset)
{
	if (position < 0)
		return B_BAD_VALUE;

	const uint64 payloadOffset = static_cast<uint64>(position);
	const uint64 headerBytes = static_cast<uint64>(kPayloadOffsetSectors)
		* device.sectorSize;
	if (payloadOffset > UINT64_MAX - headerBytes)
		return B_BAD_VALUE;
	offset = headerBytes + payloadOffset;
	if (offset > static_cast<uint64>(OFF_MAX))
		return B_BAD_VALUE;
	return B_OK;
}


static status_t
BackingOffsetAndLengthForPayload(const Device& device, off_t position,
	size_t length, uint64& offset)
{
	status_t status = BackingOffsetForPayload(device, position, offset);
	if (status != B_OK)
		return status;
	if (length > static_cast<size_t>(OFF_MAX)
		|| offset > static_cast<uint64>(OFF_MAX) - length)
		return B_BAD_VALUE;
	return B_OK;
}


static status_t
CheckedIO(Device& device, off_t position, size_t* numBytes)
{
	if (numBytes == NULL)
		return B_BAD_VALUE;
	if (!device.unlocked)
		return B_NOT_ALLOWED;
	if (position < 0)
		return B_BAD_VALUE;
	if ((static_cast<uint64>(position) % device.sectorSize) != 0
		|| ((*numBytes % device.sectorSize) != 0))
		return B_BAD_VALUE;

	const uint64 payloadBytes = PayloadBytes(device);
	if (payloadBytes == 0)
		return B_BAD_VALUE;
	if (static_cast<uint64>(position) > payloadBytes)
		return B_BAD_VALUE;
	const uint64 remainingBytes = payloadBytes - static_cast<uint64>(position);
	if (static_cast<uint64>(*numBytes) > remainingBytes)
		*numBytes = static_cast<size_t>(remainingBytes);
	return B_OK;
}


static void
ComputeGeometry(device_geometry& geometry, uint64 blockCount, uint32 blockSize)
{
	geometry.head_count = 1;
	while (blockCount > UINT32_MAX) {
		geometry.head_count <<= 1;
		blockCount >>= 1;
	}

	geometry.cylinder_count = 1;
	geometry.sectors_per_track = static_cast<uint32>(blockCount);
	geometry.bytes_per_sector = blockSize;
}


static status_t
CryptSectors(Device& device, off_t position, uint8* buffer, size_t length,
	bool encrypt)
{
	const uint64 firstSector = static_cast<uint64>(position)
		/ device.sectorSize;
	const size_t sectorSize = device.sectorSize;

	for (size_t offset = 0; offset < length; offset += sectorSize) {
		const uint64 sector = firstSector + (offset / sectorSize);
		if (xts_haiku_crypt(device.xts, sector, NULL, buffer + offset,
				sectorSize, encrypt) != 0)
			return B_IO_ERROR;
	}

	return B_OK;
}


status_t
DeviceUnlock(Device& device, const encrypted_home_ioctl_unlock& request)
{
	MutexLocker locker(device.lock);
	if (!device.registered)
		return B_BAD_VALUE;
	if (request.cipherId != kCipherAES128XTS && request.cipherId != kCipherAES256XTS)
		return B_BAD_VALUE;
	if ((request.cipherId == kCipherAES128XTS && request.masterKeyLength != 32)
		|| (request.cipherId == kCipherAES256XTS
			&& request.masterKeyLength != 64))
		return B_BAD_VALUE;
	if (device.unlocked)
		return B_BUSY;

	void* keyAddress = NULL;
	device.keyArea = create_area("encrypted home master key", &keyAddress,
		B_ANY_KERNEL_ADDRESS, B_PAGE_SIZE, B_FULL_LOCK,
		B_KERNEL_READ_AREA | B_KERNEL_WRITE_AREA);
	if (device.keyArea < B_OK)
		return device.keyArea;

	device.xts = static_cast<xts_haiku_context*>(
		malloc(sizeof(xts_haiku_context)));
	if (device.xts == NULL) {
		delete_area(device.keyArea);
		device.keyArea = -1;
		return B_NO_MEMORY;
	}

	device.key = static_cast<uint8*>(keyAddress);
	memcpy(device.key, request.masterKey, request.masterKeyLength);
	device.keyLength = request.masterKeyLength;
	device.cipherId = request.cipherId;
	if (xts_haiku_init(device.xts, device.key, device.keyLength) != 0) {
		DeviceLock(device);
		return B_BAD_VALUE;
	}

	device.unlocked = true;
	return B_OK;
}


status_t
DeviceLock(Device& device)
{
	if (device.xts != NULL) {
		xts_haiku_clear(device.xts);
		free(device.xts);
		device.xts = NULL;
	}
	if (device.key != NULL) {
		SecureZero(device.key, B_PAGE_SIZE);
		device.key = NULL;
	}
	if (device.keyArea >= B_OK) {
		delete_area(device.keyArea);
		device.keyArea = -1;
	}
	device.keyLength = 0;
	device.cipherId = 0;
	device.unlocked = false;
	return B_OK;
}


status_t
DeviceRead(Device& device, off_t position, void* buffer, size_t* numBytes)
{
	MutexLocker locker(device.lock);
	status_t status = CheckedIO(device, position, numBytes);
	if (status != B_OK)
		return status;
	if (*numBytes == 0)
		return B_OK;

	uint8* transfer = static_cast<uint8*>(malloc(kMaxRawIOTransferBytes));
	if (transfer == NULL)
		return B_NO_MEMORY;

	uint8* out = static_cast<uint8*>(buffer);
	size_t processed = 0;
	while (processed < *numBytes) {
		const size_t chunkLength = min_c(kMaxRawIOTransferBytes,
			*numBytes - processed);
		const uint64 chunkPosition64 = static_cast<uint64>(position)
			+ processed;
		if (chunkPosition64 > static_cast<uint64>(OFF_MAX)) {
			status = B_BAD_VALUE;
			break;
		}
		const off_t chunkPosition = static_cast<off_t>(chunkPosition64);
		uint64 backingOffset = 0;
		status = BackingOffsetAndLengthForPayload(device, chunkPosition,
			chunkLength, backingOffset);
		if (status != B_OK)
			break;

		ssize_t bytesRead = read_pos(device.backingFD,
			static_cast<off_t>(backingOffset), transfer, chunkLength);
		if (bytesRead < 0) {
			status = errno;
			break;
		}
		if (static_cast<size_t>(bytesRead) != chunkLength) {
			status = B_IO_ERROR;
			break;
		}

		status = CryptSectors(device, chunkPosition, transfer, chunkLength,
			false);
		if (status != B_OK)
			break;

		status = user_memcpy(out + processed, transfer, chunkLength);
		if (status != B_OK)
			break;
		SecureZero(transfer, chunkLength);
		processed += chunkLength;
	}

	SecureZero(transfer, kMaxRawIOTransferBytes);
	free(transfer);
	return status;
}


status_t
DeviceWrite(Device& device, off_t position, const void* buffer, size_t* numBytes)
{
	MutexLocker locker(device.lock);
	status_t status = CheckedIO(device, position, numBytes);
	if (status != B_OK)
		return status;
	if (*numBytes == 0)
		return B_OK;

	uint8* transfer = static_cast<uint8*>(malloc(kMaxRawIOTransferBytes));
	if (transfer == NULL)
		return B_NO_MEMORY;

	const uint8* in = static_cast<const uint8*>(buffer);
	size_t processed = 0;
	while (processed < *numBytes) {
		const size_t chunkLength = min_c(kMaxRawIOTransferBytes,
			*numBytes - processed);
		const uint64 chunkPosition64 = static_cast<uint64>(position)
			+ processed;
		if (chunkPosition64 > static_cast<uint64>(OFF_MAX)) {
			status = B_BAD_VALUE;
			break;
		}
		const off_t chunkPosition = static_cast<off_t>(chunkPosition64);
		uint64 backingOffset = 0;
		status = BackingOffsetAndLengthForPayload(device, chunkPosition,
			chunkLength, backingOffset);
		if (status != B_OK)
			break;

		status = user_memcpy(transfer, in + processed, chunkLength);
		if (status != B_OK)
			break;

		status = CryptSectors(device, chunkPosition, transfer, chunkLength,
			true);
		if (status != B_OK)
			break;

		ssize_t bytesWritten = write_pos(device.backingFD,
			static_cast<off_t>(backingOffset), transfer, chunkLength);
		if (bytesWritten < 0) {
			status = errno;
			break;
		}
		if (static_cast<size_t>(bytesWritten) != chunkLength) {
			status = B_IO_ERROR;
			break;
		}
		SecureZero(transfer, chunkLength);
		processed += chunkLength;
	}

	SecureZero(transfer, kMaxRawIOTransferBytes);
	free(transfer);
	return status;
}


status_t
DeviceControl(Device& device, uint32 op, void* buffer, size_t length)
{
	switch (op) {
		case IOCTL_ENCRYPTED_HOME_UNLOCK:
		{
			if (buffer == NULL || length != sizeof(encrypted_home_ioctl_unlock))
				return B_BAD_VALUE;
			encrypted_home_ioctl_unlock request = {};
			status_t status = user_memcpy(&request, buffer, sizeof(request));
			if (status != B_OK) {
				SecureZero(&request, sizeof(request));
				return status;
			}
			status = DeviceUnlock(device, request);
			SecureZero(&request, sizeof(request));
			return status;
		}

		case IOCTL_ENCRYPTED_HOME_LOCK:
		{
			MutexLocker locker(device.lock);
			if (device.openCount > 1)
				return B_BUSY;
			return DeviceLock(device);
		}

		case IOCTL_ENCRYPTED_HOME_INFO:
		{
			if (buffer == NULL || length != sizeof(encrypted_home_ioctl_info))
				return B_BAD_VALUE;
			encrypted_home_ioctl_info info = {};
			status_t status = FillDeviceInfo(device, info);
			if (status != B_OK)
				return status;
			return user_memcpy(buffer, &info, sizeof(info));
		}

		case B_GET_DEVICE_SIZE:
		{
			size_t size = static_cast<size_t>(PayloadBytes(device));
			return user_memcpy(buffer, &size, sizeof(size));
		}

		case B_GET_GEOMETRY:
		case B_GET_BIOS_GEOMETRY:
		{
			if (buffer == NULL || length > sizeof(device_geometry))
				return B_BAD_VALUE;

			device_geometry geometry = {};
			ComputeGeometry(geometry, device.payloadSizeSectors,
				device.sectorSize);
			geometry.device_type = B_DISK;
			geometry.removable = false;
			geometry.read_only = false;
			geometry.write_once = false;
			geometry.bytes_per_physical_sector = device.sectorSize;
			return user_memcpy(buffer, &geometry, length);
		}

		case B_GET_MEDIA_STATUS:
		{
			status_t mediaStatus = B_OK;
			return user_memcpy(buffer, &mediaStatus, sizeof(mediaStatus));
		}

		case B_SET_NONBLOCKING_IO:
		case B_SET_BLOCKING_IO:
			return B_OK;

		case B_GET_READ_STATUS:
		case B_GET_WRITE_STATUS:
		{
			bool ready = device.unlocked;
			return user_memcpy(buffer, &ready, sizeof(ready));
		}

		case B_FLUSH_DRIVE_CACHE:
			return fsync(device.backingFD) == 0 ? B_OK : errno;

		default:
			return B_DEV_INVALID_IOCTL;
	}
}


} // namespace BPrivate::EncryptedHome::Kernel
