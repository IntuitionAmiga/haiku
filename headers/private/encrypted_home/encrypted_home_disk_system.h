/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef _PRIVATE_ENCRYPTED_HOME_DISK_SYSTEM_H
#define _PRIVATE_ENCRYPTED_HOME_DISK_SYSTEM_H


#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <SupportDefs.h>


namespace BPrivate::EncryptedHome {

static const char kEncryptedHomeMagic[] = "HAIKUENC";
static const size_t kEncryptedHomeMagicSize = 8;
static const uint64 kEncryptedHomeBackupHeaderSectors = 8;
static const uint64 kEncryptedHomePayloadOffsetSectors = 16;
static const uint16 kEncryptedHomeHeaderVersion = 1;
static const uint32 kEncryptedHomeCipherAES128XTS = 1;
static const uint32 kEncryptedHomeCipherAES256XTS = 2;
static const uint32 kEncryptedHomeKdfArgon2id = 1;
static const char kEncryptedHomeDiskSystemShortName[] = "encrypted_home";
static const char kEncryptedHomeDiskSystemPrettyName[] = "Encrypted Home";

struct EncryptedHomeHeaderProbe {
	uint32 sectorSize;
	uint64 payloadSizeSectors;
};

static inline bool
HasEncryptedHomeMagic(const void* buffer, size_t size)
{
	return buffer != NULL && size >= kEncryptedHomeMagicSize
		&& memcmp(buffer, kEncryptedHomeMagic, kEncryptedHomeMagicSize) == 0;
}


static inline uint32
ReadEncryptedHomeLE32(const void* buffer, size_t offset)
{
	const uint8* bytes = static_cast<const uint8*>(buffer);
	return static_cast<uint32>(bytes[offset])
		| (static_cast<uint32>(bytes[offset + 1]) << 8)
		| (static_cast<uint32>(bytes[offset + 2]) << 16)
		| (static_cast<uint32>(bytes[offset + 3]) << 24);
}


static inline uint16
ReadEncryptedHomeLE16(const void* buffer, size_t offset)
{
	const uint8* bytes = static_cast<const uint8*>(buffer);
	return static_cast<uint16>(bytes[offset])
		| static_cast<uint16>(bytes[offset + 1]) << 8;
}


static inline uint64
ReadEncryptedHomeLE64(const void* buffer, size_t offset)
{
	return static_cast<uint64>(ReadEncryptedHomeLE32(buffer, offset))
		| (static_cast<uint64>(ReadEncryptedHomeLE32(buffer, offset + 4))
			<< 32);
}


static inline bool
EncryptedHomeRangeIsZero(const void* buffer, size_t offset, size_t length)
{
	const uint8* bytes = static_cast<const uint8*>(buffer);
	for (size_t index = 0; index < length; index++) {
		if (bytes[offset + index] != 0)
			return false;
	}

	return true;
}


static inline bool
EncryptedHomeSectorSizeSupported(uint32 sectorSize)
{
	return sectorSize == 512 || sectorSize == 4096;
}


static inline bool
EncryptedHomeCipherSupported(uint32 cipherId)
{
	return cipherId == kEncryptedHomeCipherAES128XTS
		|| cipherId == kEncryptedHomeCipherAES256XTS;
}


static inline bool
EncryptedHomeKdfParametersAreBounded(uint32 timeCost, uint32 memoryCostKiB,
	uint32 parallelism)
{
	return timeCost > 0 && timeCost <= 10
		&& memoryCostKiB > 0 && memoryCostKiB <= 65536
		&& parallelism > 0 && parallelism <= 16
		&& memoryCostKiB >= parallelism * 8;
}


static inline uint64
EncryptedHomeBackupHeaderOffset(uint32 sectorSize)
{
	return kEncryptedHomeBackupHeaderSectors * sectorSize;
}


static inline bool
EncryptedHomePayloadSizeValid(uint64 payloadSizeSectors)
{
	return payloadSizeSectors != 0;
}


static inline bool
EncryptedHomePayloadFitsPartition(uint64 payloadSizeSectors, uint32 sectorSize,
	uint64 partitionSizeBytes, uint64* _payloadBytes = NULL)
{
	if (!EncryptedHomePayloadSizeValid(payloadSizeSectors) || sectorSize == 0)
		return false;

	if (payloadSizeSectors > UINT64_MAX / sectorSize)
		return false;

	uint64 payloadBytes = payloadSizeSectors * sectorSize;
	uint64 headerBytes = kEncryptedHomePayloadOffsetSectors * sectorSize;
	if (headerBytes > UINT64_MAX - payloadBytes)
		return false;

	if (headerBytes + payloadBytes > partitionSizeBytes)
		return false;

	if (_payloadBytes != NULL)
		*_payloadBytes = payloadBytes;
	return true;
}


static inline bool
EncryptedHomeParseHeaderProbe(const void* buffer, size_t size,
	uint64 partitionSizeBytes, uint32 expectedSectorSize,
	EncryptedHomeHeaderProbe* _probe)
{
	if (size < 0x20 || !HasEncryptedHomeMagic(buffer, size))
		return false;

	if (size < 4096)
		return false;

	if (ReadEncryptedHomeLE16(buffer, 0x08) != kEncryptedHomeHeaderVersion)
		return false;
	if (ReadEncryptedHomeLE16(buffer, 0x0a) != 0)
		return false;

	uint32 sectorSize = ReadEncryptedHomeLE32(buffer, 0x0c);
	if (!EncryptedHomeSectorSizeSupported(sectorSize))
		return false;
	if (expectedSectorSize != 0 && sectorSize != expectedSectorSize)
		return false;

	uint64 payloadOffsetSectors = ReadEncryptedHomeLE64(buffer, 0x10);
	if (payloadOffsetSectors != kEncryptedHomePayloadOffsetSectors)
		return false;

	uint64 payloadSizeSectors = ReadEncryptedHomeLE64(buffer, 0x18);
	if (!EncryptedHomePayloadFitsPartition(payloadSizeSectors, sectorSize,
			partitionSizeBytes)) {
		return false;
	}

	uint32 cipherId = ReadEncryptedHomeLE32(buffer, 0x20);
	if (!EncryptedHomeCipherSupported(cipherId))
		return false;
	if (ReadEncryptedHomeLE32(buffer, 0x24) != kEncryptedHomeKdfArgon2id)
		return false;
	if (!EncryptedHomeKdfParametersAreBounded(
			ReadEncryptedHomeLE32(buffer, 0x28),
			ReadEncryptedHomeLE32(buffer, 0x2c),
			ReadEncryptedHomeLE32(buffer, 0x30))) {
		return false;
	}
	if (!EncryptedHomeRangeIsZero(buffer, 0x34, 12))
		return false;
	if (cipherId == kEncryptedHomeCipherAES128XTS
		&& !EncryptedHomeRangeIsZero(buffer, 0x98, 32)) {
		return false;
	}
	if (ReadEncryptedHomeLE32(buffer, 0xb8) == 0)
		return false;
	if (!EncryptedHomeRangeIsZero(buffer, 0xbc, 4)
		|| !EncryptedHomeRangeIsZero(buffer, 0xe0, 4096 - 0xe0)) {
		return false;
	}

	if (_probe != NULL) {
		_probe->sectorSize = sectorSize;
		_probe->payloadSizeSectors = payloadSizeSectors;
	}
	return true;
}


static inline bool
EncryptedHomeSupportsInitializing()
{
	return false;
}


static inline status_t
EncryptedHomeValidateInitialize()
{
	return B_NOT_SUPPORTED;
}


static inline status_t
EncryptedHomeMountUnsupported()
{
	return B_NOT_SUPPORTED;
}

} // namespace BPrivate::EncryptedHome


#endif	// _PRIVATE_ENCRYPTED_HOME_DISK_SYSTEM_H
