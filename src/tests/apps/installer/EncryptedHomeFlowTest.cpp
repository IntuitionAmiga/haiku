/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedHomeProvisioner.h"

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

#include <sys/stat.h>
#include <unistd.h>

#include <Errors.h>
#include <SupportDefs.h>

#include <encrypted_home_disk_system.h>


namespace {

using BPrivate::EncryptedHome::Installer::EncryptedHomeInstallOptions;
using BPrivate::EncryptedHome::Installer::EncryptedHomeProvisioner;
using BPrivate::EncryptedHome::Installer::ProvisionedEncryptedHome;


std::span<const std::byte>
Bytes(std::string_view string)
{
	return {reinterpret_cast<const std::byte*>(string.data()), string.size()};
}


bool
Expect(bool condition, const char* message)
{
	if (!condition)
		std::fprintf(stderr, "FAIL: %s\n", message);
	return condition;
}


std::string
ReadFile(const char* path)
{
	std::FILE* file = std::fopen(path, "r");
	if (file == NULL)
		return {};

	std::string contents;
	std::array<char, 256> buffer;
	while (size_t bytes = std::fread(buffer.data(), 1, buffer.size(), file))
		contents.append(buffer.data(), bytes);
	std::fclose(file);
	return contents;
}


bool
PathExists(const char* path)
{
	struct stat stat;
	return lstat(path, &stat) == 0;
}


bool
IsDirectory(const char* path)
{
	struct stat stat;
	return lstat(path, &stat) == 0 && S_ISDIR(stat.st_mode);
}


void
RemoveSettingsTree(const char* root)
{
	std::string settings = std::string(root)
		+ "/system/settings/encrypted_home";
	std::string settingsDirectory = std::string(root) + "/system/settings";
	std::string systemDirectory = std::string(root) + "/system";
	unlink(settings.c_str());
	rmdir(settingsDirectory.c_str());
	rmdir(systemDirectory.c_str());
	rmdir(root);
}


void
RemoveHomeTree(const char* root)
{
	std::string oldFile = std::string(root) + "/home/plaintext";
	std::string home = std::string(root) + "/home";
	unlink(oldFile.c_str());
	rmdir(home.c_str());
	rmdir(root);
}


bool
TestValidation()
{
	EncryptedHomeInstallOptions options;
	options.enabled = true;
	options.sourcePartitionID = 9;
	options.targetPartitionID = 10;
	options.homePartitionID = 11;
	options.cipherId = BPrivate::EncryptedHome::kEncryptedHomeCipherAES256XTS;
	options.passphrase = Bytes("correct horse battery staple");
	options.confirmation = Bytes("correct horse battery staple");

	bool ok = true;
	ok &= Expect(EncryptedHomeProvisioner::Validate(options) == B_OK,
		"valid encrypted-home install options accepted");

	options.homePartitionID = options.targetPartitionID;
	ok &= Expect(EncryptedHomeProvisioner::Validate(options) == B_BAD_VALUE,
		"single-partition encrypted-home install rejected");
	options.homePartitionID = 11;

	options.homePartitionID = options.sourcePartitionID;
	ok &= Expect(EncryptedHomeProvisioner::Validate(options) == B_BAD_VALUE,
		"source partition as encrypted-home backing rejected");
	options.homePartitionID = 11;

	options.confirmation = Bytes("different passphrase");
	ok &= Expect(EncryptedHomeProvisioner::Validate(options)
			== B_MISMATCHED_VALUES,
		"mismatched passphrase confirmation rejected");
	options.confirmation = options.passphrase;

	options.passphrase = Bytes("");
	options.confirmation = Bytes("");
	ok &= Expect(EncryptedHomeProvisioner::Validate(options) == B_BAD_VALUE,
		"empty passphrase rejected");
	options.passphrase = Bytes("correct horse battery staple");
	options.confirmation = options.passphrase;

	options.cipherId = 99;
	ok &= Expect(EncryptedHomeProvisioner::Validate(options) == B_BAD_VALUE,
		"unknown cipher rejected");

	options.enabled = false;
	options.targetPartitionID = options.homePartitionID;
	options.passphrase = Bytes("");
	options.confirmation = Bytes("does not matter");
	ok &= Expect(EncryptedHomeProvisioner::Validate(options) == B_OK,
		"disabled encrypted-home install ignores encrypted options");

	return ok;
}


bool
TestBackingContentEligibility()
{
	bool ok = true;
	ok &= Expect(EncryptedHomeProvisioner::IsSafeBackingContent(
			B_PARTITION_UNINITIALIZED, false, false, NULL),
		"manually uninitialized home backing partition accepted");
	ok &= Expect(EncryptedHomeProvisioner::IsSafeBackingContent(
			B_PARTITION_VALID, false, false, NULL),
		"empty valid home backing partition accepted");
	ok &= Expect(!EncryptedHomeProvisioner::IsSafeBackingContent(
			B_PARTITION_VALID, true, false, "Be File System"),
		"existing file system as home backing rejected");
	ok &= Expect(!EncryptedHomeProvisioner::IsSafeBackingContent(
			B_PARTITION_VALID, false, true, "Intel Partition Map"),
		"nested partition map as home backing rejected");
	ok &= Expect(!EncryptedHomeProvisioner::IsSafeBackingContent(
			B_PARTITION_UNRECOGNIZED, false, false, NULL),
		"unrecognized existing data as home backing rejected");
	return ok;
}


bool
TestPayloadCapacityExcludesHeaderSectors()
{
	bool ok = true;
	auto tooSmall = EncryptedHomeProvisioner::PayloadBytes(16 * 512, 512);
	ok &= Expect(!tooSmall.has_value(),
		"backing partition without payload capacity rejected");

	auto payload = EncryptedHomeProvisioner::PayloadBytes(64 * 512, 512);
	ok &= Expect(payload.has_value(), "payload capacity accepted");
	if (payload.has_value()) {
		ok &= Expect(*payload == 48 * 512,
			"payload capacity excludes encrypted-home header reservation");
	}

	auto unsupported = EncryptedHomeProvisioner::PayloadBytes(64 * 1024, 1024);
	ok &= Expect(!unsupported.has_value(),
		"unsupported backing sector size rejected for capacity checks");
	return ok;
}


bool
TestMkfsRunsNonInteractively()
{
	BString command = EncryptedHomeProvisioner::BuildMkfsCommand(
		"/dev/disk/encrypted_home/0/raw");
	return Expect(command == "mkfs -q -t bfs "
			"\"/dev/disk/encrypted_home/0/raw\" EncryptedHome",
		"encrypted-home mkfs command runs non-interactively");
}


bool
TestPrepareMountPointPreservesExistingHome()
{
	char target[] = "/tmp/EncryptedHomeFlowTest-XXXXXX";
	if (mkdtemp(target) == NULL)
		return Expect(false, "temporary target created");

	std::string home = std::string(target) + "/home";
	std::string oldFile = home + "/plaintext";
	bool ok = true;
	ok &= Expect(mkdir(home.c_str(), 0755) == 0,
		"existing plaintext home directory created");
	std::FILE* file = std::fopen(oldFile.c_str(), "w");
	ok &= Expect(file != NULL, "existing plaintext home file created");
	if (file != NULL) {
		std::fputs("old unencrypted home data", file);
		std::fclose(file);
	}

	ok &= Expect(EncryptedHomeProvisioner::PrepareMountPoint(target)
			== B_NOT_ALLOWED,
		"encrypted-home mount point rejects non-empty existing home");
	ok &= Expect(IsDirectory(home.c_str()),
		"existing home directory preserved");
	ok &= Expect(PathExists(oldFile.c_str()),
		"old plaintext home data preserved before install completes");

	RemoveHomeTree(target);
	return ok;
}


bool
TestWriteSettingsCreatesParentsAndOverwritesSourceState()
{
	char target[] = "/tmp/EncryptedHomeFlowTest-XXXXXX";
	if (mkdtemp(target) == NULL)
		return Expect(false, "temporary target created");

	ProvisionedEncryptedHome provisioned;
	provisioned.volumeUuid = "00112233445566778899aabbccddeeff";

	bool ok = true;
	ok &= Expect(EncryptedHomeProvisioner::WriteSettings(target, provisioned)
			== B_OK,
		"encrypted-home settings parent directories created");

	std::string settingsPath = std::string(target)
		+ "/system/settings/encrypted_home";
	ok &= Expect(ReadFile(settingsPath.c_str())
			== "enabled true\nvolume_uuid 00112233445566778899aabbccddeeff\n",
		"encrypted-home settings contain provisioned UUID");

	std::FILE* settings = std::fopen(settingsPath.c_str(), "w");
	if (settings != NULL) {
		std::fputs("enabled true\nvolume_uuid stale-source-volume\n",
			settings);
		std::fclose(settings);
	}

	provisioned.volumeUuid = "ffeeddccbbaa99887766554433221100";
	ok &= Expect(EncryptedHomeProvisioner::WriteSettings(target, provisioned)
			== B_OK,
		"encrypted-home settings rewritten after source copy");
	ok &= Expect(ReadFile(settingsPath.c_str())
			== "enabled true\nvolume_uuid ffeeddccbbaa99887766554433221100\n",
		"stale source encrypted-home UUID overwritten");

	RemoveSettingsTree(target);
	return ok;
}


bool
TestRemoveSettingsWhenEncryptedHomeDisabled()
{
	char target[] = "/tmp/EncryptedHomeFlowTest-XXXXXX";
	if (mkdtemp(target) == NULL)
		return Expect(false, "temporary target created");

	ProvisionedEncryptedHome provisioned;
	provisioned.volumeUuid = "00112233445566778899aabbccddeeff";

	bool ok = true;
	ok &= Expect(EncryptedHomeProvisioner::WriteSettings(target, provisioned)
			== B_OK,
		"stale encrypted-home settings created");

	std::string settingsPath = std::string(target)
		+ "/system/settings/encrypted_home";
	ok &= Expect(EncryptedHomeProvisioner::RemoveSettings(target) == B_OK,
		"encrypted-home settings removed when option disabled");
	ok &= Expect(!PathExists(settingsPath.c_str()),
		"disabled encrypted-home install does not leave stale settings");

	RemoveSettingsTree(target);
	return ok;
}


} // namespace


int
main()
{
	if (!TestValidation())
		return 1;
	if (!TestBackingContentEligibility())
		return 1;
	if (!TestPayloadCapacityExcludesHeaderSectors())
		return 1;
	if (!TestMkfsRunsNonInteractively())
		return 1;
	if (!TestPrepareMountPointPreservesExistingHome())
		return 1;
	if (!TestWriteSettingsCreatesParentsAndOverwritesSourceState())
		return 1;
	if (!TestRemoveSettingsWhenEncryptedHomeDisabled())
		return 1;
	return 0;
}
