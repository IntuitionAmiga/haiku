/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedHomeProvisioner.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <Directory.h>
#include <Errors.h>
#include <Entry.h>
#include <Path.h>
#include <Partition.h>
#include <String.h>
#include <fs_volume.h>

#include <encrypted_block_translator.h>
#include <encrypted_home_disk_system.h>
#include <encrypted_home_driver.h>
#include <encrypted_volume_header.h>
#include <settings_format.h>
#include <openssl/crypto.h>


namespace BPrivate::EncryptedHome::Installer {

namespace {

constexpr size_t kMaxInstallerPassphraseLength = 1024;
constexpr std::array<char, 16> kHexDigits = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

BString
HexUuid(std::span<const std::byte, 16> uuid)
{
	BString hex;
	for (std::byte byte : uuid) {
		uint8 value = std::to_integer<uint8>(byte);
		hex << kHexDigits[value >> 4];
		hex << kHexDigits[value & 0x0f];
	}
	return hex;
}


status_t
CreateDirectoryPath(const char* path, mode_t mode)
{
	if (path == NULL || path[0] == '\0')
		return B_BAD_VALUE;

	BString current;
	const char* component = path;
	if (*component == '/') {
		current = "/";
		while (*component == '/')
			component++;
	}

	while (*component != '\0') {
		const char* end = std::strchr(component, '/');
		size_t length = end != NULL
			? static_cast<size_t>(end - component) : std::strlen(component);
		if (length != 0) {
			if (!current.IsEmpty() && current != "/")
				current << "/";
			current.Append(component, static_cast<int32>(length));

			BEntry entry(current.String());
			if (entry.Exists()) {
				if (!entry.IsDirectory())
					return B_BAD_VALUE;
			} else {
				status_t status = create_directory(current.String(), mode);
				if (status != B_OK && status != B_FILE_EXISTS)
					return status;
			}
		}

		if (end == NULL)
			break;
		component = end + 1;
		while (*component == '/')
			component++;
	}

	return B_OK;
}


status_t
DirectoryIsEmpty(const char* path, bool& isEmpty)
{
	struct stat stat;
	if (lstat(path, &stat) != 0)
		return errno;

	if (!S_ISDIR(stat.st_mode) || S_ISLNK(stat.st_mode))
		return B_BAD_VALUE;

	DIR* directory = opendir(path);
	if (directory == NULL)
		return errno;

	isEmpty = true;
	while (dirent* entry = readdir(directory)) {
		if (std::strcmp(entry->d_name, ".") == 0
			|| std::strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		isEmpty = false;
		break;
	}

	if (closedir(directory) != 0)
		return errno;
	return B_OK;
}


bool
PathExists(const char* path)
{
	struct stat stat;
	return lstat(path, &stat) == 0;
}


} // namespace


void
ProvisionedEncryptedHome::Cleanup() const
{
	if (mountPoint.InitCheck() == B_OK)
		fs_unmount_volume(mountPoint.Path(), 0);
	if (registrationID < 0)
		return;

	BString controlPath("/dev/");
	controlPath << ENCRYPTED_HOME_CONTROL_DEVICE_NAME;
	int control = open(controlPath.String(), O_RDWR);
	if (control < 0)
		return;

	encrypted_home_ioctl_unregister unregisterRequest = {};
	unregisterRequest.id = registrationID;
	ioctl(control, IOCTL_ENCRYPTED_HOME_UNREGISTER, &unregisterRequest,
		sizeof(unregisterRequest));
	close(control);
}


status_t
EncryptedHomeProvisioner::Validate(const EncryptedHomeInstallOptions& options)
{
	if (!options.enabled)
		return B_OK;

	if (options.sourcePartitionID < 0 || options.targetPartitionID < 0
		|| options.homePartitionID < 0)
		return B_BAD_VALUE;
	if (options.sourcePartitionID == options.homePartitionID)
		return B_BAD_VALUE;
	if (options.targetPartitionID == options.homePartitionID)
		return B_BAD_VALUE;
	if (options.passphrase.empty())
		return B_BAD_VALUE;
	if (options.passphrase.size() > kMaxInstallerPassphraseLength)
		return B_BAD_VALUE;
	if (options.passphrase.size() != options.confirmation.size())
		return B_MISMATCHED_VALUES;
	if (!std::equal(options.passphrase.begin(), options.passphrase.end(),
			options.confirmation.begin()))
		return B_MISMATCHED_VALUES;
	if (options.cipherId != kEncryptedHomeCipherAES128XTS
		&& options.cipherId != kEncryptedHomeCipherAES256XTS)
		return B_BAD_VALUE;

	return B_OK;
}


bool
EncryptedHomeProvisioner::IsSafeBackingContent(uint32 status,
	bool containsFileSystem, bool containsPartitioningSystem,
	const char* contentType)
{
	if (containsFileSystem || containsPartitioningSystem)
		return false;
	if (status == B_PARTITION_UNINITIALIZED)
		return true;
	return status == B_PARTITION_VALID && contentType == NULL;
}


std::expected<uint64, status_t>
EncryptedHomeProvisioner::PayloadBytes(off_t backingBytes, uint32 sectorSize)
{
	if (!EncryptedHomeSectorSizeSupported(sectorSize))
		return std::unexpected(B_BAD_VALUE);
	if (backingBytes <= static_cast<off_t>(
			kEncryptedHomePayloadOffsetSectors * sectorSize))
		return std::unexpected(B_BAD_VALUE);

	uint64 payloadSectors = static_cast<uint64>(backingBytes / sectorSize
		- kEncryptedHomePayloadOffsetSectors);
	return payloadSectors * sectorSize;
}


std::expected<ProvisionedEncryptedHome, status_t>
EncryptedHomeProvisioner::Provision(BPartition& homePartition,
	const char* targetDirectory, const EncryptedHomeInstallOptions& options)
{
	status_t validation = Validate(options);
	if (validation != B_OK)
		return std::unexpected(validation);
	if (!options.enabled)
		return {};

	if (!IsSafeBackingContent(homePartition.Status(),
			homePartition.ContainsFileSystem(),
			homePartition.ContainsPartitioningSystem(),
			homePartition.ContentType())) {
		return std::unexpected(B_BAD_VALUE);
	}

	BPath backingPath;
	status_t status = homePartition.GetPath(&backingPath);
	if (status != B_OK)
		return std::unexpected(status);

	uint32 sectorSize = homePartition.BlockSize();
	auto payloadBytes = PayloadBytes(homePartition.Size(), sectorSize);
	if (!payloadBytes.has_value())
		return std::unexpected(payloadBytes.error());

	status = PrepareMountPoint(targetDirectory);
	if (status != B_OK)
		return std::unexpected(status);

	FormatOptions formatOptions;
	formatOptions.sectorSize = sectorSize;
	formatOptions.payloadSizeSectors = *payloadBytes / sectorSize;
	formatOptions.cipherId = options.cipherId;

	std::FILE* file = std::fopen(backingPath.Path(), "r+b");
	if (file == NULL)
		return std::unexpected(errno);

	FileBackingStore store(file);
	auto translator = EncryptedBlockTranslator::Format(store,
		options.passphrase, formatOptions);
	if (!translator.has_value()) {
		std::fclose(file);
		return std::unexpected(translator.error());
	}
	auto closeResult = translator->Close();
	if (!closeResult.has_value()) {
		std::fclose(file);
		return std::unexpected(closeResult.error());
	}

	HeaderBytes header = {};
	auto readHeader = store.ReadAt(0, header);
	if (!readHeader.has_value()) {
		std::fclose(file);
		return std::unexpected(readHeader.error());
	}
	std::fclose(file);

	auto parsed = EncryptedVolumeHeader::Parse(header);
	if (!parsed.has_value())
		return std::unexpected(parsed.error());
	auto unlocked = EncryptedVolumeHeader::Unlock(header, options.passphrase);
	if (!unlocked.has_value())
		return std::unexpected(unlocked.error());

	BString controlPath("/dev/");
	controlPath << ENCRYPTED_HOME_CONTROL_DEVICE_NAME;
	int control = open(controlPath.String(), O_RDWR);
	if (control < 0)
		return std::unexpected(errno);

	struct stat backingStat;
	if (stat(backingPath.Path(), &backingStat) != 0) {
		close(control);
		return std::unexpected(errno);
	}

	encrypted_home_ioctl_register registration = {};
	registration.backingDevice = S_ISREG(backingStat.st_mode)
		? backingStat.st_dev : backingStat.st_rdev;
	registration.sectorSize = formatOptions.sectorSize;
	registration.payloadSizeSectors = formatOptions.payloadSizeSectors;
	strlcpy(registration.backingPath, backingPath.Path(),
		sizeof(registration.backingPath));
	if (ioctl(control, IOCTL_ENCRYPTED_HOME_REGISTER, &registration,
			sizeof(registration)) != 0) {
		close(control);
		return std::unexpected(errno);
	}
	close(control);
	auto unregisterDevice = [&registration, &controlPath]() {
		int unregisterControl = open(controlPath.String(), O_RDWR);
		if (unregisterControl < 0)
			return;
		encrypted_home_ioctl_unregister unregisterRequest = {};
		unregisterRequest.id = registration.id;
		ioctl(unregisterControl, IOCTL_ENCRYPTED_HOME_UNREGISTER,
			&unregisterRequest, sizeof(unregisterRequest));
		close(unregisterControl);
	};

	BString rawPath("/dev/");
	rawPath << registration.rawPath;
	int raw = open(rawPath.String(), O_RDWR);
	if (raw < 0) {
		unregisterDevice();
		return std::unexpected(errno);
	}

	encrypted_home_ioctl_unlock unlockRequest = {};
	unlockRequest.cipherId = unlocked->cipherId;
	unlockRequest.masterKeyLength = unlocked->masterKeyLength;
	std::memcpy(unlockRequest.masterKey, unlocked->masterKey.data(),
		unlocked->masterKeyLength);
	if (ioctl(raw, IOCTL_ENCRYPTED_HOME_UNLOCK, &unlockRequest,
			sizeof(unlockRequest)) != 0) {
		OPENSSL_cleanse(&unlockRequest, sizeof(unlockRequest));
		close(raw);
		unregisterDevice();
		return std::unexpected(errno);
	}
	OPENSSL_cleanse(&unlockRequest, sizeof(unlockRequest));
	close(raw);
	BString command = BuildMkfsCommand(rawPath.String());
	if (system(command.String()) != 0) {
		unregisterDevice();
		return std::unexpected(B_ERROR);
	}

	BPath targetHome(targetDirectory, "home");
	dev_t mounted = fs_mount_volume(targetHome.Path(), rawPath.String(), "bfs",
		0, NULL);
	if (mounted < 0) {
		unregisterDevice();
		return std::unexpected(mounted);
	}

	BString uuid = HexUuid(parsed->volumeUuid);
	return ProvisionedEncryptedHome{targetHome, uuid, registration.id};
}


BString
EncryptedHomeProvisioner::BuildMkfsCommand(const char* rawPath)
{
	BString command;
	command.SetToFormat("mkfs -q -t bfs \"%s\" EncryptedHome", rawPath);
	return command;
}


status_t
EncryptedHomeProvisioner::PrepareMountPoint(const char* targetDirectory)
{
	BPath targetHome(targetDirectory, "home");
	status_t status = targetHome.InitCheck();
	if (status != B_OK)
		return status;

	if (!PathExists(targetHome.Path())) {
		status = create_directory(targetHome.Path(), 0755);
		if (status != B_OK && status != B_FILE_EXISTS)
			return status;
		return B_OK;
	}

	bool isEmpty = false;
	status = DirectoryIsEmpty(targetHome.Path(), isEmpty);
	if (status != B_OK)
		return status;
	if (!isEmpty)
		return B_NOT_ALLOWED;
	return B_OK;
}


status_t
EncryptedHomeProvisioner::RemoveSettings(const char* targetDirectory)
{
	BPath settingsPath(targetDirectory, settings::kTargetSettingsPath);
	status_t status = settingsPath.InitCheck();
	if (status != B_OK)
		return status;

	if (unlink(settingsPath.Path()) != 0 && errno != ENOENT)
		return errno;
	return B_OK;
}


status_t
EncryptedHomeProvisioner::WriteSettings(const char* targetDirectory,
	const ProvisionedEncryptedHome& provisionedHome)
{
	BPath settingsDirectory(targetDirectory, settings::kTargetSettingsDirectory);
	status_t status = settingsDirectory.InitCheck();
	if (status != B_OK)
		return status;
	status = CreateDirectoryPath(settingsDirectory.Path(), 0755);
	if (status != B_OK)
		return status;

	BPath settingsPath(settingsDirectory.Path(), settings::kSettingsFileName);
	std::FILE* settingsFile = std::fopen(settingsPath.Path(), "w");
	if (settingsFile == NULL)
		return errno;
	if (std::fprintf(settingsFile, "%s %s\n%s %s\n", settings::kEnabledKey,
			settings::kEnabledTrueValue, settings::kVolumeUuidKey,
			provisionedHome.volumeUuid.String()) < 0) {
		status_t writeStatus = errno;
		std::fclose(settingsFile);
		return writeStatus;
	}
	if (std::fclose(settingsFile) != 0)
		return errno;
	return B_OK;
}


} // namespace BPrivate::EncryptedHome::Installer
