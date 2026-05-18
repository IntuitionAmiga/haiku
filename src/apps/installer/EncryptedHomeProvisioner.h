/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef ENCRYPTED_HOME_PROVISIONER_H
#define ENCRYPTED_HOME_PROVISIONER_H


#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

#include <SupportDefs.h>

#include <DiskDeviceDefs.h>
#include <Path.h>
#include <String.h>

class BPartition;


namespace BPrivate::EncryptedHome::Installer {

struct EncryptedHomeInstallOptions {
	bool enabled = false;
	partition_id sourcePartitionID = -1;
	partition_id targetPartitionID = -1;
	partition_id homePartitionID = -1;
	uint32 cipherId = 0;
	std::span<const std::byte> passphrase;
	std::span<const std::byte> confirmation;
};


struct ProvisionedEncryptedHome {
	BPath mountPoint;
	BString volumeUuid;
	int32 registrationID = -1;

	void Cleanup() const;
};


class EncryptedHomeProvisioner {
public:
	[[nodiscard]] static status_t Validate(
		const EncryptedHomeInstallOptions& options);
	[[nodiscard]] static bool IsSafeBackingContent(uint32 status,
		bool containsFileSystem, bool containsPartitioningSystem,
		const char* contentType);
	[[nodiscard]] static std::expected<uint32, status_t> BackingSectorSize(
		uint32 blockSize, uint32 physicalBlockSize);
	[[nodiscard]] static std::expected<uint64, status_t> PayloadBytes(
		off_t backingBytes, uint32 sectorSize);
	[[nodiscard]] static std::expected<ProvisionedEncryptedHome, status_t>
		Provision(BPartition& homePartition, const char* targetDirectory,
			const EncryptedHomeInstallOptions& options);
	[[nodiscard]] static BString BuildMkfsCommand(const char* rawPath);
	[[nodiscard]] static status_t PrepareMountPoint(const char* targetDirectory);
	[[nodiscard]] static status_t RemoveSettings(const char* targetDirectory);
	[[nodiscard]] static status_t WriteSettings(const char* targetDirectory,
		const ProvisionedEncryptedHome& provisionedHome);
};

} // namespace BPrivate::EncryptedHome::Installer


#endif	// ENCRYPTED_HOME_PROVISIONER_H
