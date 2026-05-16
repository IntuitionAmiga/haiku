/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <encrypted_home_disk_system.h>

#include <new>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <disk_device_manager.h>
#include <fs_interface.h>


using namespace BPrivate::EncryptedHome;


namespace {

struct identify_cookie {
	uint32 sectorSize;
	uint64 payloadSizeSectors;
};


bool
payload_size_fits_partition(const identify_cookie& cookie,
	const partition_data& partition, off_t* _payloadBytes)
{
	if (partition.size < 0)
		return false;

	uint64 payloadBytes = 0;
	if (!EncryptedHomePayloadFitsPartition(cookie.payloadSizeSectors,
			cookie.sectorSize, static_cast<uint64>(partition.size),
			&payloadBytes)) {
		return false;
	}

	if (payloadBytes > static_cast<uint64>(INT64_MAX))
		return false;

	*_payloadBytes = static_cast<off_t>(payloadBytes);
	return true;
}


bool
read_header_probe(int fd, off_t offset, const partition_data& partition,
	uint32 expectedSectorSize, identify_cookie& cookie)
{
	char header[4096];
	ssize_t bytesRead = read_pos(fd, offset, header, sizeof(header));
	if (bytesRead < 0)
		return false;

	EncryptedHomeHeaderProbe probe;
	if (!EncryptedHomeParseHeaderProbe(header, static_cast<size_t>(bytesRead),
			static_cast<uint64>(partition.size), expectedSectorSize, &probe)) {
		return false;
	}

	cookie.sectorSize = probe.sectorSize;
	cookie.payloadSizeSectors = probe.payloadSizeSectors;
	return true;
}


float
encrypted_home_identify_partition(int fd, partition_data* partition,
	void** _cookie)
{
	if (partition == NULL || partition->size < 0)
		return -1;

	identify_cookie* cookie = new(std::nothrow) identify_cookie;
	if (cookie == NULL)
		return -1;

	bool found = read_header_probe(fd, 0, *partition, 0, *cookie)
		|| read_header_probe(fd, EncryptedHomeBackupHeaderOffset(512),
			*partition, 512, *cookie)
		|| read_header_probe(fd, EncryptedHomeBackupHeaderOffset(4096),
			*partition, 4096, *cookie);
	if (!found) {
		delete cookie;
		return -1;
	}

	*_cookie = cookie;
	return 0.80f;
}


status_t
encrypted_home_scan_partition(int fd, partition_data* partition, void* _cookie)
{
	(void)fd;

	identify_cookie* cookie = static_cast<identify_cookie*>(_cookie);
	if (partition == NULL || cookie == NULL)
		return B_BAD_VALUE;

	off_t payloadBytes = 0;
	if (!payload_size_fits_partition(*cookie, *partition, &payloadBytes))
		return B_BAD_DATA;

	partition->status = B_PARTITION_VALID;
	partition->flags |= B_PARTITION_FILE_SYSTEM;
	partition->block_size = cookie->sectorSize;
	partition->content_size = payloadBytes;
	partition->content_name = strdup("");

	return partition->content_name != NULL ? B_OK : B_NO_MEMORY;
}


void
encrypted_home_free_identify_partition_cookie(partition_data* partition,
	void* _cookie)
{
	(void)partition;

	identify_cookie* cookie = static_cast<identify_cookie*>(_cookie);
	delete cookie;
}


uint32
encrypted_home_get_supported_operations(partition_data* partition, uint32 mask)
{
	(void)partition;
	(void)mask;

	return 0;
}


bool
encrypted_home_validate_initialize(partition_data* partition, char* name,
	const char* parameters)
{
	(void)partition;
	(void)name;
	(void)parameters;

	return EncryptedHomeSupportsInitializing();
}


status_t
encrypted_home_mount(fs_volume* volume, const char* device, uint32 flags,
	const char* args, ino_t* _rootVnodeID)
{
	(void)volume;
	(void)device;
	(void)flags;
	(void)args;
	(void)_rootVnodeID;

	return EncryptedHomeMountUnsupported();
}

} // namespace


static file_system_module_info sEncryptedHomeFileSystem = {
	{
		"file_systems/encrypted_home" B_CURRENT_FS_API_VERSION,
		0,
		NULL,
	},

	kEncryptedHomeDiskSystemShortName,
	kEncryptedHomeDiskSystemPrettyName,

	B_DISK_SYSTEM_IS_FILE_SYSTEM,

	encrypted_home_identify_partition,
	encrypted_home_scan_partition,
	encrypted_home_free_identify_partition_cookie,
	NULL,

	encrypted_home_mount,

	encrypted_home_get_supported_operations,

	NULL,
	NULL,
	NULL,
	NULL,
	encrypted_home_validate_initialize,

	NULL,

	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};


module_info* modules[] = {
	reinterpret_cast<module_info*>(&sEncryptedHomeFileSystem),
	NULL
};
