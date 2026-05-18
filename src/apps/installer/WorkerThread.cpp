/*
 * Copyright 2009, Stephan Aßmus <superstippi@gmx.de>.
 * Copyright 2005-2008, Jérôme DUVAL.
 * All rights reserved. Distributed under the terms of the MIT License.
 */

#include "WorkerThread.h"

#include <errno.h>
#include <stdio.h>

#ifdef ENCRYPTED_HOME_AVAILABLE
#	include <limits>
#	include <optional>
#endif
#include <set>
#include <string>
#include <strings.h>

#include <Alert.h>
#include <Autolock.h>
#include <Catalog.h>
#include <Directory.h>
#include <DiskDeviceVisitor.h>
#include <DiskDeviceTypes.h>
#include <FindDirectory.h>
#include <fs_index.h>
#include <Locale.h>
#include <Menu.h>
#include <MenuItem.h>
#include <Message.h>
#include <Messenger.h>
#include <Path.h>
#include <String.h>
#include <VolumeRoster.h>

#include "AutoLocker.h"
#include "CopyEngine.h"
#ifdef ENCRYPTED_HOME_AVAILABLE
#	include "EncryptedHomeProvisioner.h"
#endif
#include "InstallerDefs.h"
#include "PackageViews.h"
#include "PartitionMenuItem.h"
#include "ProgressReporter.h"
#include "StringForSize.h"
#include "UnzipEngine.h"


#define B_TRANSLATION_CONTEXT "InstallProgress"


//#define COPY_TRACE
#ifdef COPY_TRACE
#define CALLED() 		printf("CALLED %s\n",__PRETTY_FUNCTION__)
#define ERR2(x, y...)	fprintf(stderr, "WorkerThread: "x" %s\n", y, strerror(err))
#define ERR(x)			fprintf(stderr, "WorkerThread: "x" %s\n", strerror(err))
#else
#define CALLED()
#define ERR(x)
#define ERR2(x, y...)
#endif

const char BOOT_PATH[] = "/boot";

const uint32 MSG_START_INSTALLING = 'eSRT';

#ifdef ENCRYPTED_HOME_AVAILABLE
using BPrivate::EncryptedHome::Installer::EncryptedHomeInstallOptions;
using BPrivate::EncryptedHome::Installer::ProvisionedEncryptedHome;
#endif


class SourceVisitor : public BDiskDeviceVisitor {
public:
	SourceVisitor(BMenu* menu);
	virtual bool Visit(BDiskDevice* device);
	virtual bool Visit(BPartition* partition, int32 level);

private:
	BMenu* fMenu;
};


class TargetVisitor : public BDiskDeviceVisitor {
public:
	TargetVisitor(BMenu* menu);
	virtual bool Visit(BDiskDevice* device);
	virtual bool Visit(BPartition* partition, int32 level);

private:
	BMenu* fMenu;
};


#ifdef ENCRYPTED_HOME_AVAILABLE
class HomeVisitor : public BDiskDeviceVisitor {
public:
	HomeVisitor(BMenu* menu, BMenu* sourceMenu, partition_id bootPartitionID);
	virtual bool Visit(BDiskDevice* device);
	virtual bool Visit(BPartition* partition, int32 level);

private:
			bool				_IsInstallSource(partition_id id) const;

	BMenu* fMenu;
	BMenu* fSourceMenu;
	partition_id fBootPartitionID;
};
#endif


class EFIVisitor : public BDiskDeviceVisitor {
public:
	EFIVisitor(BMenu* menu, partition_id bootId);
	virtual bool Visit(BDiskDevice* device);
	virtual bool Visit(BPartition* partition, int32 level);

private:
	BMenu* fMenu;
	partition_id fBootId;
};


// #pragma mark - WorkerThread


class WorkerThread::EntryFilter : public CopyEngine::EntryFilter {
public:
	EntryFilter(const char* sourceDirectory)
		:
		fIgnorePaths(),
		fSourceDevice(-1)
	{
		try {
			fIgnorePaths.insert(kPackagesDirectoryPath);
			fIgnorePaths.insert(kSourcesDirectoryPath);
			fIgnorePaths.insert("rr_moved");
			fIgnorePaths.insert("boot.catalog");
			fIgnorePaths.insert("haiku-boot-floppy.image");
			fIgnorePaths.insert("system/var/swap");
			fIgnorePaths.insert("system/var/shared_memory");
			fIgnorePaths.insert("system/var/log/syslog");
			fIgnorePaths.insert("system/var/log/syslog.old");
			fIgnorePaths.insert("system/settings/ssh/ssh_host_ecdsa_key");
			fIgnorePaths.insert("system/settings/ssh/ssh_host_ecdsa_key.pub");
			fIgnorePaths.insert("system/settings/ssh/ssh_host_ed25519_key");
			fIgnorePaths.insert("system/settings/ssh/ssh_host_ed25519_key.pub");
			fIgnorePaths.insert("system/settings/ssh/ssh_host_rsa_key");
			fIgnorePaths.insert("system/settings/ssh/ssh_host_rsa_key.pub");

			fPackageFSRootPaths.insert("system");
			fPackageFSRootPaths.insert("home/config");
		} catch (std::bad_alloc&) {
		}

		struct stat st;
		if (stat(sourceDirectory, &st) == 0)
			fSourceDevice = st.st_dev;
	}

	virtual bool ShouldCopyEntry(const BEntry& entry, const char* path,
		const struct stat& statInfo) const
	{
		if (S_ISBLK(statInfo.st_mode) || S_ISCHR(statInfo.st_mode)
				|| S_ISFIFO(statInfo.st_mode) || S_ISSOCK(statInfo.st_mode)) {
			printf("skipping '%s', it is a special file.\n", path);
			return false;
		}

		if (fIgnorePaths.find(path) != fIgnorePaths.end()) {
			printf("ignoring '%s'.\n", path);
			return false;
		}

		if (statInfo.st_dev != fSourceDevice) {
			// Allow that only for the root of the packagefs mounts, since
			// those contain directories that shine through from the
			// underlying volume.
			if (fPackageFSRootPaths.find(path) == fPackageFSRootPaths.end())
				return false;
		}

		return true;
	}

private:
	typedef std::set<std::string> StringSet;

			StringSet			fIgnorePaths;
			StringSet			fPackageFSRootPaths;
			dev_t				fSourceDevice;
};


#ifdef ENCRYPTED_HOME_AVAILABLE
static const char*
RelativePath(const BString& sourceRoot, const char* path)
{
	size_t rootLength = sourceRoot.Length();
	if (strncmp(path, sourceRoot.String(), rootLength) != 0)
		return path;
	if (path[rootLength] == '/')
		return path + rootLength + 1;
	if (path[rootLength] == '\0')
		return "";
	return path;
}


static status_t
CollectCopyBytes(const BString& sourceRoot, CopyEngine::EntryFilter& filter,
	BEntry& entry, off_t& bytes)
{
	struct stat statInfo;
	status_t ret = entry.GetStat(&statInfo);
	if (ret != B_OK)
		return ret;

	BPath path(&entry);
	ret = path.InitCheck();
	if (ret != B_OK)
		return ret;

	if (!filter.ShouldCopyEntry(entry, RelativePath(sourceRoot, path.Path()),
			statInfo)) {
		return B_OK;
	}

	if (S_ISDIR(statInfo.st_mode)) {
		BDirectory directory(&entry);
		ret = directory.InitCheck();
		if (ret != B_OK)
			return ret;

		BEntry child;
		while (directory.GetNextEntry(&child) == B_OK) {
			ret = CollectCopyBytes(sourceRoot, filter, child, bytes);
			if (ret != B_OK)
				return ret;
		}
	} else if (!S_ISLNK(statInfo.st_mode)) {
		if (statInfo.st_size > std::numeric_limits<off_t>::max() - bytes)
			return B_BAD_VALUE;
		bytes += statInfo.st_size;
	}

	return B_OK;
}
#endif


// #pragma mark - WorkerThread


WorkerThread::WorkerThread(const BMessenger& owner)
	:
	BLooper("copy_engine"),
	fOwner(owner),
	fPackages(NULL),
	fSpaceRequired(0),
	fCancelSemaphore(-1)
#ifdef ENCRYPTED_HOME_AVAILABLE
	,
	fEncryptedHomeOptions(),
	fEncryptedHomePassphrase(),
	fEncryptedHomePassphraseLength(0)
#endif
{
	Run();
}


void
WorkerThread::MessageReceived(BMessage* message)
{
	CALLED();

	switch (message->what) {
		case MSG_START_INSTALLING:
			_PerformInstall(message->GetInt32("source", -1),
				message->GetInt32("target", -1));
			break;

		case MSG_WRITE_BOOT_SECTOR:
		{
			int32 id;
			if (message->FindInt32("id", &id) != B_OK) {
				_SetStatusMessage(B_TRANSLATE("Boot sector not written "
					"because of an internal error."));
				break;
			}

			// TODO: Refactor with _PerformInstall()
			BPath targetDirectory;
			BDiskDevice device;
			BPartition* partition;

			if (fDDRoster.GetPartitionWithID(id, &device, &partition) == B_OK) {
				if (!partition->IsMounted()) {
					if (partition->Mount() < B_OK) {
						_SetStatusMessage(B_TRANSLATE("The partition can't be "
							"mounted. Please choose a different partition."));
						break;
					}
				}
				if (partition->GetMountPoint(&targetDirectory) != B_OK) {
					_SetStatusMessage(B_TRANSLATE("The mount point could not "
						"be retrieved."));
					break;
				}
			} else if (fDDRoster.GetDeviceWithID(id, &device) == B_OK) {
				if (!device.IsMounted()) {
					if (device.Mount() < B_OK) {
						_SetStatusMessage(B_TRANSLATE("The disk can't be "
							"mounted. Please choose a different disk."));
						break;
					}
				}
				if (device.GetMountPoint(&targetDirectory) != B_OK) {
					_SetStatusMessage(B_TRANSLATE("The mount point could not "
						"be retrieved."));
					break;
				}
			}

			if (_WriteBootSector(targetDirectory) != B_OK) {
				_SetStatusMessage(
					B_TRANSLATE("Error writing boot sector."));
				break;
			}
			_SetStatusMessage(
				B_TRANSLATE("Boot sector successfully written."));
		}
		default:
			BLooper::MessageReceived(message);
	}
}


static BString
arch_efi_default_prefix()
{
#if defined(__i386__)
	return BString("BOOTIA32");
#elif defined(__x86_64__)
	return BString("BOOTX64");
#elif defined(__arm__) || defined(__ARM__)
	return BString("BOOTARM");
#elif defined(__aarch64__) || defined(__arm64__)
	return BString("BOOTAA64");
#elif defined(__riscv) && __riscv_xlen == 32
	return BString("BOOTRISCV32");
#elif defined(__riscv) && __riscv_xlen == 64
	return BString("BOOTRISCV64");
#else
	#error "Error: Unknown EFI Architecture!"
#endif
}


void
WorkerThread::InstallEFILoader(partition_id id, bool rename)
{
	// Executed in window thread.
	BDiskDevice device;
	BPartition* partition;
	BDirectory destDir;
	BPath loaderPath;
	BFile loaderToCopy;
	BFile loaderDest;
	BPath destPath;
	BEntry existingEntry;
	off_t size = 0;
	BString errText;
	status_t err = B_OK;

	BString archLoader = arch_efi_default_prefix();
	archLoader.Append(".EFI");
	BString archLoaderBackup = arch_efi_default_prefix();
	archLoaderBackup.Append("_old.EFI");

	if (find_directory(B_SYSTEM_DATA_DIRECTORY, &loaderPath) != B_OK
		|| loaderPath.Append("platform_loaders/haiku_loader.efi") != B_OK
		|| loaderToCopy.SetTo(loaderPath.Path(), B_READ_ONLY) != B_OK
		|| loaderToCopy.InitCheck() != B_OK
		|| loaderToCopy.GetSize(&size) != B_OK)
		errText.SetTo(B_TRANSLATE("Failed to find EFI loader file!"));

	char* buffer = NULL;
	if (errText.IsEmpty())
		buffer = new char[size];
	if (errText.IsEmpty() && loaderToCopy.Read(buffer, size) != size)
		errText.SetTo(B_TRANSLATE("Failed to read EFI loader file!"));

	if (errText.IsEmpty()
		&& (fDDRoster.GetPartitionWithID(id, &device, &partition) != B_OK
		|| (!partition->IsMounted() && partition->Mount() != B_OK)
		|| partition->GetMountPoint(&destPath) != B_OK))
		errText.SetTo(B_TRANSLATE("Failed to access installation destination!"));

	if (errText.IsEmpty()
		&& (destPath.Append("EFI/BOOT") != B_OK
		|| create_directory(destPath.Path(), 0755) != B_OK
		|| destDir.SetTo(destPath.Path()) != B_OK
		|| destDir.InitCheck() != B_OK))
		errText.SetTo(B_TRANSLATE("Failed to create EFI loader directory!"));

	if (errText.IsEmpty() && rename
		&& (destDir.FindEntry(archLoader, &existingEntry) != B_OK
		|| existingEntry.Rename(archLoaderBackup, true) != B_OK))
		errText.SetTo(B_TRANSLATE("Failed to rename existing loader!"));

	if (errText.IsEmpty()
		&& (err = destDir.CreateFile(archLoader, &loaderDest, true)) == B_FILE_EXISTS) {
		BAlert* confirmAlert = new BAlert("", B_TRANSLATE("An EFI loader is already installed "
			"on the selected partition! Would you like to rename it?"),
			B_TRANSLATE("Rename"), B_TRANSLATE("Cancel"));
		confirmAlert->SetFlags(confirmAlert->Flags() | B_CLOSE_ON_ESCAPE);
		if (confirmAlert->Go() == 0)
			InstallEFILoader(id, true);
		delete[] buffer;
		return;
	} else if (errText.IsEmpty() && (err != B_OK || loaderDest.Write(buffer, size) != size))
		errText.SetTo(B_TRANSLATE("Failed to copy EFI loader to selected partition!"));

	delete[] buffer;
	BAlert* alert = new BAlert("", B_TRANSLATE("EFI loader successfully installed!"),
		B_TRANSLATE("OK"));
	alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
	alert->SetType(B_INFO_ALERT);
	if (!errText.IsEmpty()) {
		alert->SetType(B_STOP_ALERT);
		alert->SetText(errText);
	}
	alert->Go();
}


void
WorkerThread::ScanDisksPartitions(BMenu* srcMenu, BMenu* targetMenu,
	BMenu* EFIMenu, BMenu* homeMenu)
{
	// NOTE: This is actually executed in the window thread.
	BDiskDevice device;
	BPartition *partition = NULL;

	SourceVisitor srcVisitor(srcMenu);
	fDDRoster.VisitEachMountedPartition(&srcVisitor, &device, &partition);

	TargetVisitor targetVisitor(targetMenu);
	fDDRoster.VisitEachPartition(&targetVisitor, &device, &partition);

	BDiskDevice bootDevice;
	BPartition* bootPartition = NULL;
	partition_id bootId = -1;
	if (fDDRoster.FindPartitionByMountPoint(BOOT_PATH, &bootDevice, &bootPartition) == B_OK
		&& bootPartition != NULL)
		bootId = bootPartition->ID();

#ifdef ENCRYPTED_HOME_AVAILABLE
	if (homeMenu != NULL) {
		HomeVisitor homeVisitor(homeMenu, srcMenu, bootId);
		fDDRoster.VisitEachPartition(&homeVisitor, &device, &partition);
	}
#else
	(void)homeMenu;
	(void)bootId;
#endif

	partition_id bootDiskId = bootPartition != NULL && bootPartition->Parent() != NULL
		? bootPartition->Parent()->ID() : -1;
	EFIVisitor EFIVisitor(EFIMenu, bootDiskId);
	fDDRoster.VisitEachPartition(&EFIVisitor, &device, &partition);
}


void
WorkerThread::SetPackagesList(BList *list)
{
	// Executed in window thread.
	BAutolock _(this);

	delete fPackages;
	fPackages = list;
}


void
WorkerThread::StartInstall(partition_id sourcePartitionID,
	partition_id targetPartitionID)
{
#ifdef ENCRYPTED_HOME_AVAILABLE
	EncryptedHomeInstallOptions options;
	StartInstall(sourcePartitionID, targetPartitionID, options);
#else
	// Executed in window thread.
	BMessage message(MSG_START_INSTALLING);
	message.AddInt32("source", sourcePartitionID);
	message.AddInt32("target", targetPartitionID);

	PostMessage(&message, this);
#endif
}


#ifdef ENCRYPTED_HOME_AVAILABLE
void
WorkerThread::StartInstall(partition_id sourcePartitionID,
	partition_id targetPartitionID,
	const EncryptedHomeInstallOptions& encryptedHomeOptions)
{
	// Executed in window thread.
	_ClearEncryptedHomePassphrase();
	fEncryptedHomeOptions = encryptedHomeOptions;
	if (encryptedHomeOptions.enabled) {
		fEncryptedHomePassphraseLength = encryptedHomeOptions.passphrase.size();
		if (fEncryptedHomePassphraseLength <= fEncryptedHomePassphrase.size()) {
			std::copy(encryptedHomeOptions.passphrase.begin(),
				encryptedHomeOptions.passphrase.end(),
				fEncryptedHomePassphrase.data());
			fEncryptedHomeOptions.passphrase = {
				fEncryptedHomePassphrase.data(),
				fEncryptedHomePassphraseLength
			};
			fEncryptedHomeOptions.confirmation = fEncryptedHomeOptions.passphrase;
		}
	}

	BMessage message(MSG_START_INSTALLING);
	message.AddInt32("source", sourcePartitionID);
	message.AddInt32("target", targetPartitionID);

	PostMessage(&message, this);
}
#endif


#ifdef ENCRYPTED_HOME_AVAILABLE
void
WorkerThread::_ClearEncryptedHomePassphrase()
{
	fEncryptedHomePassphrase.Cleanse();
	fEncryptedHomePassphraseLength = 0;
	fEncryptedHomeOptions.passphrase = {};
	fEncryptedHomeOptions.confirmation = {};
}
#endif


void
WorkerThread::WriteBootSector(BMenu* targetMenu)
{
	// Executed in window thread.
	CALLED();

	PartitionMenuItem* item = (PartitionMenuItem*)targetMenu->FindMarked();
	if (item == NULL) {
		ERR("bad menu items\n");
		return;
	}

	BMessage message(MSG_WRITE_BOOT_SECTOR);
	message.AddInt32("id", item->ID());
	PostMessage(&message, this);
}


// #pragma mark -


status_t
WorkerThread::_WriteBootSector(BPath &path)
{
	BPath bootPath;
	find_directory(B_BEOS_BOOT_DIRECTORY, &bootPath);
	BString command;
	command.SetToFormat("makebootable \"%s\"", path.Path());
	_SetStatusMessage(B_TRANSLATE("Writing bootsector."));
	return system(command.String());
}


status_t
WorkerThread::_LaunchFinishScript(BPath &path)
{
	_SetStatusMessage(B_TRANSLATE("Finishing installation."));

	BString command;
	command.SetToFormat("mkdir -p \"%s/system/cache/tmp\"", path.Path());
	if (system(command.String()) != 0)
		return B_ERROR;
	command.SetToFormat("mkdir -p \"%s/system/packages/administrative\"",
		path.Path());
	if (system(command.String()) != 0)
		return B_ERROR;

	// Ask for first boot processing of all the packages copied into the new
	// installation, since by just copying them the normal package processing
	// isn't done.  package_daemon will detect the magic file and do it.
	command.SetToFormat("echo 'First Boot written by Installer.' > "
		"\"%s/system/packages/administrative/FirstBootProcessingNeeded\"",
		path.Path());
	if (system(command.String()) != 0)
		return B_ERROR;

	command.SetToFormat("rm -f \"%s/home/Desktop/Installer\"", path.Path());
	return system(command.String());
}


status_t
WorkerThread::_PerformInstall(partition_id sourcePartitionID,
	partition_id targetPartitionID)
{
	CALLED();

#ifdef ENCRYPTED_HOME_AVAILABLE
	struct PassphraseCleanup {
		WorkerThread* worker;
		~PassphraseCleanup()
		{
			worker->_ClearEncryptedHomePassphrase();
		}
	} passphraseCleanup { this };
#endif

	BPath targetDirectory;
	BPath srcDirectory;
	BPath trashPath;
	BPath testPath;
	BDirectory targetDir;
	BDiskDevice device;
	BPartition* partition;
	BVolume targetVolume;
	status_t err = B_OK;
	int32 entries = 0;
	entry_ref testRef;
	const char* mountError = B_TRANSLATE("The disk can't be mounted. Please "
		"choose a different disk.");

	if (sourcePartitionID < 0 || targetPartitionID < 0) {
		ERR("bad source or target partition ID\n");
		return _InstallationError(err);
	}

	// check if target is initialized
	// ask if init or mount as is
	if (fDDRoster.GetPartitionWithID(targetPartitionID, &device,
			&partition) == B_OK) {
		if (!partition->IsMounted()) {
			if ((err = partition->Mount()) < B_OK) {
				_SetStatusMessage(mountError);
				ERR("BPartition::Mount");
				return _InstallationError(err);
			}
		}
		if ((err = partition->GetVolume(&targetVolume)) != B_OK) {
			ERR("BPartition::GetVolume");
			return _InstallationError(err);
		}
		if ((err = partition->GetMountPoint(&targetDirectory)) != B_OK) {
			ERR("BPartition::GetMountPoint");
			return _InstallationError(err);
		}
	} else if (fDDRoster.GetDeviceWithID(targetPartitionID, &device) == B_OK) {
		if (!device.IsMounted()) {
			if ((err = device.Mount()) < B_OK) {
				_SetStatusMessage(mountError);
				ERR("BDiskDevice::Mount");
				return _InstallationError(err);
			}
		}
		if ((err = device.GetVolume(&targetVolume)) != B_OK) {
			ERR("BDiskDevice::GetVolume");
			return _InstallationError(err);
		}
		if ((err = device.GetMountPoint(&targetDirectory)) != B_OK) {
			ERR("BDiskDevice::GetMountPoint");
			return _InstallationError(err);
		}
	} else
		return _InstallationError(err);  // shouldn't happen

	// check if target has enough space
	if (fSpaceRequired > 0 && targetVolume.FreeBytes() < fSpaceRequired) {
		BAlert* alert = new BAlert("", B_TRANSLATE("The destination disk may "
			"not have enough space. Try choosing a different disk or choose "
			"to not install optional items."),
			B_TRANSLATE("Try installing anyway"), B_TRANSLATE("Cancel"), 0,
			B_WIDTH_AS_USUAL, B_STOP_ALERT);
		alert->SetShortcut(1, B_ESCAPE);
		if (alert->Go() != 0)
			return _InstallationError(err);
	}

	if (fDDRoster.GetPartitionWithID(sourcePartitionID, &device, &partition)
			== B_OK) {
		if ((err = partition->GetMountPoint(&srcDirectory)) != B_OK) {
			ERR("BPartition::GetMountPoint");
			return _InstallationError(err);
		}
	} else if (fDDRoster.GetDeviceWithID(sourcePartitionID, &device) == B_OK) {
		if ((err = device.GetMountPoint(&srcDirectory)) != B_OK) {
			ERR("BDiskDevice::GetMountPoint");
			return _InstallationError(err);
		}
	} else
		return _InstallationError(err); // shouldn't happen

	// check not installing on itself
	if (strcmp(srcDirectory.Path(), targetDirectory.Path()) == 0) {
		_SetStatusMessage(B_TRANSLATE("You can't install the contents of a "
			"disk onto itself. Please choose a different disk."));
		return _InstallationError(err);
	}

	// check not installing on boot volume
	if (strncmp(BOOT_PATH, targetDirectory.Path(), strlen(BOOT_PATH)) == 0) {
		BString text(B_TRANSLATE("Are you sure you want to "
		"install onto the current boot disk? The %appname% will have to "
		"reboot your machine if you proceed."));
		text.ReplaceFirst("%appname%", B_TRANSLATE_SYSTEM_NAME("Installer"));
		BAlert* alert = new BAlert("", text, B_TRANSLATE("OK"),
			B_TRANSLATE("Cancel"), 0, B_WIDTH_AS_USUAL, B_STOP_ALERT);
		alert->SetShortcut(1, B_ESCAPE);
		if (alert->Go() != 0) {
			_SetStatusMessage("Installation stopped.");
			return _InstallationError(err);
		}
	}

	// check if target volume's trash dir has anything in it
	// (target volume w/ only an empty trash dir is considered
	// an empty volume)
	if (find_directory(B_TRASH_DIRECTORY, &trashPath, false,
		&targetVolume) == B_OK && targetDir.SetTo(trashPath.Path()) == B_OK) {
			while (targetDir.GetNextRef(&testRef) == B_OK) {
				// Something in the Trash
				entries++;
				break;
			}
	}

	targetDir.SetTo(targetDirectory.Path());

	// check if target volume otherwise has any entries
	while (entries == 0 && targetDir.GetNextRef(&testRef) == B_OK) {
		if (testPath.SetTo(&testRef) == B_OK && testPath != trashPath)
			entries++;
	}

	if (entries != 0) {
		BAlert* alert = new BAlert("", B_TRANSLATE("The target volume is not "
			"empty. If it already contains a Haiku installation, it will be "
			"overwritten. This will remove all installed software.\n\n"
			"If you want to upgrade your system without removing installed "
			"software, see the Haiku User Guide's topic on the application "
			"\"SoftwareUpdater\" for update instructions.\n\n"
			"Are you sure you want to continue the installation?"),
			B_TRANSLATE("Install anyway"), B_TRANSLATE("Cancel"), 0,
			B_WIDTH_AS_USUAL, B_STOP_ALERT);
		alert->SetShortcut(1, B_ESCAPE);
		if (alert->Go() != 0) {
		// TODO: Would be cool to offer the option here to clean additional
		// folders at the user's choice.
			return _InstallationError(B_CANCELED);
		}
		err = _PrepareCleanInstall(targetDirectory);
		if (err != B_OK)
			return _InstallationError(err);
	}

#ifdef ENCRYPTED_HOME_AVAILABLE
	std::optional<ProvisionedEncryptedHome> provisionedEncryptedHome;
	if (fEncryptedHomeOptions.enabled) {
		BDiskDevice homeDevice;
		BPartition* homePartition = NULL;
		err = fDDRoster.GetPartitionWithID(
			fEncryptedHomeOptions.homePartitionID, &homeDevice,
			&homePartition);
		if (err != B_OK) {
			err = fDDRoster.GetDeviceWithID(
				fEncryptedHomeOptions.homePartitionID, &homeDevice);
			homePartition = &homeDevice;
		}
		if (err != B_OK)
			return _InstallationError(err);

		off_t encryptedHomeBytes = 0;
		err = _CollectEncryptedHomeBytes(srcDirectory, encryptedHomeBytes);
		if (err != B_OK)
			return _InstallationError(err);
		auto sectorSize = BPrivate::EncryptedHome::Installer
			::EncryptedHomeProvisioner::BackingSectorSize(
				homePartition->BlockSize(),
				homePartition->PhysicalBlockSize());
		if (!sectorSize.has_value())
			return _InstallationError(sectorSize.error());
		auto payloadBytes = BPrivate::EncryptedHome::Installer
			::EncryptedHomeProvisioner::PayloadBytes(homePartition->Size(),
				*sectorSize);
		if (!payloadBytes.has_value())
			return _InstallationError(payloadBytes.error());
		if (encryptedHomeBytes > static_cast<off_t>(*payloadBytes)) {
			_SetStatusMessage(B_TRANSLATE("The encrypted home partition does "
				"not have enough space for the selected home folder."));
			return _InstallationError(B_DEVICE_FULL);
		}

		_SetStatusMessage(B_TRANSLATE("Preparing encrypted home folder."));
		auto provisioned = BPrivate::EncryptedHome::Installer
			::EncryptedHomeProvisioner::Provision(*homePartition,
				targetDirectory.Path(), fEncryptedHomeOptions);
		if (!provisioned.has_value())
			return _InstallationError(provisioned.error());
		provisionedEncryptedHome = *provisioned;
	}
#endif
	auto installationError = [&](status_t error) {
#ifdef ENCRYPTED_HOME_AVAILABLE
		if (provisionedEncryptedHome.has_value())
			provisionedEncryptedHome->Cleanup();
#endif
		return _InstallationError(error);
	};

	// Begin actual installation

	err = [&]() -> status_t {
		ProgressReporter reporter(fOwner, new BMessage(MSG_STATUS_MESSAGE));
		EntryFilter entryFilter(srcDirectory.Path());
		CopyEngine engine(&reporter, &entryFilter);
		BList unzipEngines;

		status_t error = _CreateAndMirrorIndices(srcDirectory, targetDirectory);
		if (error != B_OK)
			return error;

#ifdef ENCRYPTED_HOME_AVAILABLE
		if (provisionedEncryptedHome.has_value()) {
			BPath sourceHome(srcDirectory.Path(), "home");
			error = sourceHome.InitCheck();
			if (error != B_OK)
				return error;
			error = _CreateAndMirrorIndices(sourceHome,
				provisionedEncryptedHome->mountPoint);
			if (error != B_OK)
				return error;
		}
#endif

		// Let the engine collect information for the progress bar later on
		engine.ResetTargets(srcDirectory.Path());
		error = engine.CollectTargets(srcDirectory.Path(), fCancelSemaphore);
		if (error != B_OK)
			return error;

		// Collect selected packages also
		if (fPackages) {
			int32 count = fPackages->CountItems();
			for (int32 i = 0; i < count; i++) {
				Package *p = static_cast<Package*>(fPackages->ItemAt(i));
				const BPath& pkgPath = p->Path();
				error = pkgPath.InitCheck();
				if (error != B_OK)
					return error;
				error = engine.CollectTargets(pkgPath.Path(), fCancelSemaphore);
				if (error != B_OK)
					return error;
			}
		}

		// collect information about all zip packages
		error = _ProcessZipPackages(srcDirectory.Path(), targetDirectory.Path(),
			&reporter, unzipEngines);
		if (error != B_OK)
			return error;

		reporter.StartTimer();

		// copy source volume
		error = engine.Copy(srcDirectory.Path(), targetDirectory.Path(),
			fCancelSemaphore);
		if (error != B_OK)
			return error;

		// copy selected packages
		if (fPackages) {
			int32 count = fPackages->CountItems();
			// FIXME: find_directory doesn't return the folder in the target
			// volume, so we are hard coding this for now.
			BPath targetPkgDir(targetDirectory.Path(), "system/packages");
			error = targetPkgDir.InitCheck();
			if (error != B_OK)
				return error;
			for (int32 i = 0; i < count; i++) {
				Package *p = static_cast<Package*>(fPackages->ItemAt(i));
				const BPath& pkgPath = p->Path();
				error = pkgPath.InitCheck();
				if (error != B_OK)
					return error;
				BPath targetPath(targetPkgDir.Path(), pkgPath.Leaf());
				error = targetPath.InitCheck();
				if (error != B_OK)
					return error;
				error = engine.Copy(pkgPath.Path(), targetPath.Path(),
					fCancelSemaphore);
				if (error != B_OK)
					return error;
			}
		}

		// Extract all zip packages. If an error occured, delete the rest of
		// the engines, but stop extracting.
		for (int32 i = 0; i < unzipEngines.CountItems(); i++) {
			UnzipEngine* engine = reinterpret_cast<UnzipEngine*>(
				unzipEngines.ItemAtFast(i));
			if (error == B_OK)
				error = engine->UnzipPackage();
			delete engine;
		}
		return error;
	}();
	if (err != B_OK)
		return installationError(err);

#ifdef ENCRYPTED_HOME_AVAILABLE
	if (provisionedEncryptedHome.has_value()) {
		err = BPrivate::EncryptedHome::Installer::EncryptedHomeProvisioner
			::WriteSettings(targetDirectory.Path(), *provisionedEncryptedHome);
		if (err != B_OK)
			return installationError(err);
	} else {
		err = BPrivate::EncryptedHome::Installer::EncryptedHomeProvisioner
			::RemoveSettings(targetDirectory.Path());
		if (err != B_OK)
			return installationError(err);
	}
#endif

	err = _WriteBootSector(targetDirectory);
	if (err != B_OK)
		return installationError(err);

	err = _LaunchFinishScript(targetDirectory);
	if (err != B_OK)
		return installationError(err);

#ifdef ENCRYPTED_HOME_AVAILABLE
	if (provisionedEncryptedHome.has_value()) {
		provisionedEncryptedHome->Cleanup();
		provisionedEncryptedHome.reset();
	}
#endif

	fOwner.SendMessage(MSG_INSTALL_FINISHED);
	return B_OK;
}


status_t
WorkerThread::_PrepareCleanInstall(const BPath& targetDirectory) const
{
	// When a target volume has files (other than the trash), the /system
	// folder will be purged, except for the /system/settings subdirectory.
	BPath systemPath(targetDirectory.Path(), "system", true);
	status_t ret = systemPath.InitCheck();
	if (ret != B_OK)
		return ret;

	BEntry systemEntry(systemPath.Path());
	ret = systemEntry.InitCheck();
	if (ret != B_OK)
		return ret;
	if (!systemEntry.Exists())
		// target does not exist, done
		return B_OK;
	if (!systemEntry.IsDirectory())
		// the system entry is a file or a symlink
		return systemEntry.Remove();

	BDirectory systemDirectory(&systemEntry);
	ret = systemDirectory.InitCheck();
	if (ret != B_OK)
		return ret;

	BEntry subEntry;
	char fileName[B_FILE_NAME_LENGTH];
	while (systemDirectory.GetNextEntry(&subEntry) == B_OK) {
		ret = subEntry.GetName(fileName);
		if (ret != B_OK)
			return ret;

		if (subEntry.IsDirectory() && strcmp(fileName, "settings") == 0) {
			// Keep the settings folder
			continue;
		} else if (subEntry.IsDirectory()) {
			ret = CopyEngine::RemoveFolder(subEntry);
			if (ret != B_OK)
				return ret;
		} else {
			ret = subEntry.Remove();
			if (ret != B_OK)
				return ret;
		}
	}

	return B_OK;
}


status_t
WorkerThread::_InstallationError(status_t error)
{
	BMessage statusMessage(MSG_RESET);
	if (error == B_CANCELED)
		_SetStatusMessage(B_TRANSLATE("Installation canceled."));
	else
		statusMessage.AddInt32("error", error);
	ERR("_PerformInstall failed");
	fOwner.SendMessage(&statusMessage);
	return error;
}


status_t
WorkerThread::_CreateAndMirrorIndices(const BPath& sourceDirectory,
	const BPath& targetDirectory) const
{
	// Create the default indices which should always be present on a proper
	// BFS volume. We don't care if the source volume does not have them.
	status_t status = _CreateDefaultIndices(targetDirectory);
	if (status != B_OK)
		return status;

	// Mirror all the indices which are present on the source volume onto
	// the target volume.
	return _MirrorIndices(sourceDirectory, targetDirectory);
}


status_t
WorkerThread::_MirrorIndices(const BPath& sourceDirectory,
	const BPath& targetDirectory) const
{
	dev_t sourceDevice = dev_for_path(sourceDirectory.Path());
	if (sourceDevice < 0)
		return (status_t)sourceDevice;
	dev_t targetDevice = dev_for_path(targetDirectory.Path());
	if (targetDevice < 0)
		return (status_t)targetDevice;
	DIR* indices = fs_open_index_dir(sourceDevice);
	if (indices == NULL) {
		printf("%s: fs_open_index_dir(): (%d) %s\n", sourceDirectory.Path(),
			errno, strerror(errno));
		// Opening the index directory will fail for example on ISO-Live
		// CDs. The default indices have already been created earlier, so
		// we simply bail.
		return B_OK;
	}
	while (dirent* index = fs_read_index_dir(indices)) {
		if (strcmp(index->d_name, "name") == 0
			|| strcmp(index->d_name, "size") == 0
			|| strcmp(index->d_name, "last_modified") == 0) {
			continue;
		}

		index_info info;
		if (fs_stat_index(sourceDevice, index->d_name, &info) != B_OK) {
			printf("Failed to mirror index %s: fs_stat_index(): (%d) %s\n",
				index->d_name, errno, strerror(errno));
			continue;
		}

		uint32 flags = 0;
			// Flags are always 0 for the moment.
		if (fs_create_index(targetDevice, index->d_name, info.type, flags)
			!= B_OK) {
			if (errno == B_FILE_EXISTS)
				continue;
			printf("Failed to mirror index %s: fs_create_index(): (%d) %s\n",
				index->d_name, errno, strerror(errno));
			continue;
		}
	}
	fs_close_index_dir(indices);
	return B_OK;
}


status_t
WorkerThread::_CreateDefaultIndices(const BPath& targetDirectory) const
{
	dev_t targetDevice = dev_for_path(targetDirectory.Path());
	if (targetDevice < 0)
		return (status_t)targetDevice;

	struct IndexInfo {
		const char* name;
		uint32_t	type;
	};

	const IndexInfo defaultIndices[] = {
		{ "BEOS:APP_SIG", B_STRING_TYPE },
		{ "BEOS:LOCALE_LANGUAGE", B_STRING_TYPE },
		{ "BEOS:LOCALE_SIGNATURE", B_STRING_TYPE },
		{ "_trk/qrylastchange", B_INT32_TYPE },
		{ "_trk/recentQuery", B_INT32_TYPE },
		{ "be:deskbar_item_status", B_STRING_TYPE }
	};

	uint32 flags = 0;
		// Flags are always 0 for the moment.

	for (uint32 i = 0; i < sizeof(defaultIndices) / sizeof(IndexInfo); i++) {
		const IndexInfo& info = defaultIndices[i];
		if (fs_create_index(targetDevice, info.name, info.type, flags)
			!= B_OK) {
			if (errno == B_FILE_EXISTS)
				continue;
			printf("Failed to create index %s: fs_create_index(): (%d) %s\n",
				info.name, errno, strerror(errno));
			return errno;
		}
	}

	return B_OK;
}


#ifdef ENCRYPTED_HOME_AVAILABLE
status_t
WorkerThread::_CollectEncryptedHomeBytes(const BPath& sourceDirectory,
	off_t& bytes) const
{
	bytes = 0;

	BPath sourceHome(sourceDirectory.Path(), "home");
	status_t ret = sourceHome.InitCheck();
	if (ret != B_OK)
		return ret;

	BEntry homeEntry(sourceHome.Path());
	ret = homeEntry.InitCheck();
	if (ret != B_OK)
		return ret;
	if (!homeEntry.Exists())
		return B_OK;

	EntryFilter filter(sourceDirectory.Path());
	BString sourceRoot(sourceDirectory.Path());
	return CollectCopyBytes(sourceRoot, filter, homeEntry, bytes);
}
#endif


status_t
WorkerThread::_ProcessZipPackages(const char* sourcePath,
	const char* targetPath, ProgressReporter* reporter, BList& unzipEngines)
{
	// TODO: Put those in the optional packages list view
	// TODO: Implement mechanism to handle dependencies between these
	// packages. (Selecting one will auto-select others.)
	BPath pkgRootDir(sourcePath, kPackagesDirectoryPath);
	BDirectory directory(pkgRootDir.Path());
	BEntry entry;
	while (directory.GetNextEntry(&entry) == B_OK) {
		char name[B_FILE_NAME_LENGTH];
		if (entry.GetName(name) != B_OK)
			continue;
		int nameLength = strlen(name);
		if (nameLength <= 0)
			continue;
		char* nameExtension = name + nameLength - 4;
		if (strcasecmp(nameExtension, ".zip") != 0)
			continue;
		printf("found .zip package: %s\n", name);

		UnzipEngine* unzipEngine = new(std::nothrow) UnzipEngine(reporter,
			fCancelSemaphore);
		if (unzipEngine == NULL || !unzipEngines.AddItem(unzipEngine)) {
			delete unzipEngine;
			return B_NO_MEMORY;
		}
		BPath path;
		entry.GetPath(&path);
		status_t ret = unzipEngine->SetTo(path.Path(), targetPath);
		if (ret != B_OK)
			return ret;

		reporter->AddItems(unzipEngine->ItemsToUncompress(),
			unzipEngine->BytesToUncompress());
	}

	return B_OK;
}


void
WorkerThread::_SetStatusMessage(const char *status)
{
	BMessage msg(MSG_STATUS_MESSAGE);
	msg.AddString("status", status);
	fOwner.SendMessage(&msg);
}


static void
make_partition_label(BPartition* partition, char* label, char* menuLabel,
	bool showContentType, bool markBootDisk)
{
	char size[20];
	string_for_size(partition->Size(), size, sizeof(size));

	BPath path;
	partition->GetPath(&path);

	BString bootMark("");
	if (markBootDisk)
		bootMark.SetTo(B_TRANSLATE_COMMENT(" (boot disk)",
			"Marks EFI partitions on boot disk - preserve leading space"));

	if (showContentType) {
		const char* type = partition->ContentType();
		if (type == NULL)
			type = B_TRANSLATE_COMMENT("Unknown type", "Partition content type");

		sprintf(label, "%s%s - %s [%s] (%s)", partition->ContentName().String(), bootMark.String(),
			size, path.Path(), type);
	} else {
		sprintf(label, "%s%s - %s [%s]", partition->ContentName().String(), bootMark.String(),
			size, path.Path());
	}

	sprintf(menuLabel, "%s%s - %s", partition->ContentName().String(), bootMark.String(), size);
}


// #pragma mark - SourceVisitor


SourceVisitor::SourceVisitor(BMenu *menu)
	: fMenu(menu)
{
}

bool
SourceVisitor::Visit(BDiskDevice *device)
{
	return Visit(device, 0);
}


bool
SourceVisitor::Visit(BPartition *partition, int32 level)
{
	BPath path;

	if (partition->ContentType() == NULL)
		return false;

	bool isBootPartition = false;
	if (partition->IsMounted()) {
		BPath mountPoint;
		if (partition->GetMountPoint(&mountPoint) != B_OK)
			return false;
		isBootPartition = strcmp(BOOT_PATH, mountPoint.Path()) == 0;
	}

	if (!isBootPartition
		&& strcmp(partition->ContentType(), kPartitionTypeBFS) != 0) {
		// Except only BFS partitions, except this is the boot partition
		// (ISO9660 with write overlay for example).
		return false;
	}

	// TODO: We could probably check if this volume contains
	// the Haiku kernel or something. Does it make sense to "install"
	// from your BFS volume containing the music collection?
	// TODO: Then the check for BFS could also be removed above.

	char label[255];
	char menuLabel[255];
	make_partition_label(partition, label, menuLabel, false, false);
	PartitionMenuItem* item = new PartitionMenuItem(partition->ContentName(),
		label, menuLabel, new BMessage(SOURCE_PARTITION), partition->ID());
	item->SetMarked(isBootPartition);
	fMenu->AddItem(item);
	return false;
}


// #pragma mark - TargetVisitor


TargetVisitor::TargetVisitor(BMenu *menu)
	: fMenu(menu)
{
}


bool
TargetVisitor::Visit(BDiskDevice *device)
{
	if (device->IsReadOnlyMedia())
		return false;
	return Visit(device, 0);
}


bool
TargetVisitor::Visit(BPartition *partition, int32 level)
{
	if (partition->ContentSize() < 20 * 1024 * 1024) {
		// reject partitions which are too small anyway
		// TODO: Could depend on the source size
		return false;
	}

	if (partition->CountChildren() > 0) {
		// Looks like an extended partition, or the device itself.
		// Do not accept this as target...
		return false;
	}

	// TODO: After running DriveSetup and doing another scan, it would
	// be great to pick the partition which just appeared!

	bool isBootPartition = false;
	if (partition->IsMounted()) {
		BPath mountPoint;
		partition->GetMountPoint(&mountPoint);
		isBootPartition = strcmp(BOOT_PATH, mountPoint.Path()) == 0;
	}

	// Only writable non-boot BFS partitions are valid targets, but we want to
	// display the other partitions as well, to inform the user that they are
	// detected but somehow not appropriate.
	bool isValidTarget = isBootPartition == false
		&& !partition->IsReadOnly()
		&& partition->ContentType() != NULL
		&& strcmp(partition->ContentType(), kPartitionTypeBFS) == 0;

	char label[255];
	char menuLabel[255];
	make_partition_label(partition, label, menuLabel, !isValidTarget, false);
	PartitionMenuItem* item = new PartitionMenuItem(partition->ContentName(),
		label, menuLabel, new BMessage(TARGET_PARTITION), partition->ID());

	item->SetIsValidTarget(isValidTarget);


	fMenu->AddItem(item);
	return false;
}


#ifdef ENCRYPTED_HOME_AVAILABLE
// #pragma mark - HomeVisitor


HomeVisitor::HomeVisitor(BMenu* menu, BMenu* sourceMenu,
	partition_id bootPartitionID)
	:
	fMenu(menu),
	fSourceMenu(sourceMenu),
	fBootPartitionID(bootPartitionID)
{
}


bool
HomeVisitor::Visit(BDiskDevice* device)
{
	if (device->IsReadOnlyMedia())
		return false;
	return Visit(device, 0);
}


bool
HomeVisitor::Visit(BPartition* partition, int32 level)
{
	if (partition->Size() < 20 * 1024 * 1024)
		return false;
	if (partition->CountChildren() > 0)
		return false;
	if (partition->IsReadOnly())
		return false;
	if (partition->ID() == fBootPartitionID)
		return false;
	if (_IsInstallSource(partition->ID()))
		return false;
	if (partition->IsMounted())
		return false;

	bool isValidTarget = BPrivate::EncryptedHome::Installer
		::EncryptedHomeProvisioner::IsSafeBackingContent(partition->Status(),
			partition->ContainsFileSystem(),
			partition->ContainsPartitioningSystem(), partition->ContentType());

	char label[255];
	char menuLabel[255];
	make_partition_label(partition, label, menuLabel, !isValidTarget, false);
	PartitionMenuItem* item = new PartitionMenuItem(partition->ContentName(),
		label, menuLabel, new BMessage(HOME_PARTITION), partition->ID());
	item->SetIsValidTarget(isValidTarget);
	item->SetRequiresEraseConfirmation(partition->ContainsFileSystem());
	fMenu->AddItem(item);
	return false;
}


bool
HomeVisitor::_IsInstallSource(partition_id id) const
{
	if (fSourceMenu == NULL)
		return false;

	for (int32 i = fSourceMenu->CountItems() - 1; i >= 0; i--) {
		PartitionMenuItem* item
			= (PartitionMenuItem*)fSourceMenu->ItemAt(i);
		if (item->ID() == id)
			return true;
	}

	return false;
}
#endif


// #pragma mark - EFIVisitor


EFIVisitor::EFIVisitor(BMenu *menu, partition_id bootId)
	:
	fMenu(menu),
	fBootId(bootId)
{
}


bool
EFIVisitor::Visit(BDiskDevice *device)
{
	if (device->IsReadOnlyMedia())
		return false;
	return Visit(device, 0);
}


bool
EFIVisitor::Visit(BPartition *partition, int32 level)
{
	// Makes sure this is a large enough writeable FAT32 non-extended EFI partition on a GUID disk
	if (partition->IsReadOnly()
		|| partition->ContentSize() < 1024 * 1024
		|| partition->CountChildren() > 0
		|| partition->Type() == NULL
		|| strcmp(partition->Type(), "EFI system data") != 0
		|| partition->ContentType() == NULL
		|| strcmp(partition->ContentType(), kPartitionTypeFAT32) != 0
		|| partition->Parent() == NULL
		|| partition->Parent()->ContentType() == NULL
		|| strcmp(partition->Parent()->ContentType(), kPartitionTypeEFI) != 0)
		return false;

	char label[255];
	char menuLabel[255];
	make_partition_label(partition, label, menuLabel, false, partition->Parent()->ID() == fBootId);
	BMessage* message = new BMessage(EFI_PARTITION);
	message->AddInt32("id", partition->ID());
	BMenuItem* item = new BMenuItem(label, message);
	fMenu->AddItem(item);
	return false;
}
