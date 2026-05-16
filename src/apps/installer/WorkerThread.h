/*
 * Copyright 2009, Stephan Aßmus <superstippi@gmx.de>.
 * Copyright 2005, Jérôme DUVAL.
 * All rights reserved. Distributed under the terms of the MIT License.
 */
#ifndef WORKER_THREAD_H
#define WORKER_THREAD_H

#include <cstddef>

#include <DiskDevice.h>
#include <DiskDeviceRoster.h>
#include <Looper.h>
#include <Messenger.h>
#include <Partition.h>
#include <Volume.h>

#ifdef ENCRYPTED_HOME_AVAILABLE
#	include "EncryptedHomeProvisioner.h"
#	include <secure_buffer.h>
#endif

class BList;
class BMenu;
class ProgressReporter;

class WorkerThread : public BLooper {
public:
								WorkerThread(const BMessenger& owner);

	virtual	void				MessageReceived(BMessage* message);

			void 				InstallEFILoader(partition_id id, bool rename);

			void				ScanDisksPartitions(BMenu* srcMenu,
									BMenu* dstMenu, BMenu* EFIMenu,
									BMenu* homeMenu);

			void				SetPackagesList(BList* list);
			void				SetSpaceRequired(off_t bytes)
									{ fSpaceRequired = bytes; };

			bool				Cancel();
			void				SetLock(sem_id cancelSemaphore)
									{ fCancelSemaphore = cancelSemaphore; }

			void				StartInstall(partition_id sourcePartitionID,
									partition_id targetPartitionID);
#ifdef ENCRYPTED_HOME_AVAILABLE
			void				StartInstall(partition_id sourcePartitionID,
									partition_id targetPartitionID,
									const BPrivate::EncryptedHome::Installer
										::EncryptedHomeInstallOptions&
											encryptedHomeOptions);
#endif
			void				WriteBootSector(BMenu* dstMenu);

private:
			status_t			_WriteBootSector(BPath& path);
			status_t			_LaunchFinishScript(BPath& path);

			status_t			_PerformInstall(partition_id sourcePartitionID,
									partition_id targetPartitionID);
			status_t			_PrepareCleanInstall(
									const BPath& targetDirectory) const;
			status_t			_InstallationError(status_t error);
			status_t			_CreateAndMirrorIndices(
									const BPath& sourceDirectory,
									const BPath& targetDirectory) const;
			status_t			_MirrorIndices(const BPath& srcDirectory,
									const BPath& targetDirectory) const;
			status_t			_CreateDefaultIndices(
									const BPath& targetDirectory) const;
			status_t			_ProcessZipPackages(const char* sourcePath,
									const char* targetPath,
									ProgressReporter* reporter,
									BList& unzipEngines);
#ifdef ENCRYPTED_HOME_AVAILABLE
			status_t			_CollectEncryptedHomeBytes(
									const BPath& sourceDirectory,
									off_t& bytes) const;
			void				_ClearEncryptedHomePassphrase();
#endif

			void				_SetStatusMessage(const char* status);

private:
			class EntryFilter;

private:
			BMessenger			fOwner;
			BDiskDeviceRoster	fDDRoster;
			BList*				fPackages;
			off_t				fSpaceRequired;
			sem_id				fCancelSemaphore;
#ifdef ENCRYPTED_HOME_AVAILABLE
			BPrivate::EncryptedHome::Installer
				::EncryptedHomeInstallOptions fEncryptedHomeOptions;
			BPrivate::EncryptedHome::secure_buffer<1024>
				fEncryptedHomePassphrase;
			size_t				fEncryptedHomePassphraseLength;
#endif
};

#endif // WORKER_THREAD_H
