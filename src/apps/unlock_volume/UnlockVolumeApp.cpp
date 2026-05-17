/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "UnlockVolumeSupport.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <span>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Woverloaded-virtual"
#pragma GCC diagnostic ignored "-Wshadow"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <Alert.h>
#include <Application.h>
#include <Button.h>
#include <Catalog.h>
#include <DiskDevice.h>
#include <DiskDeviceRoster.h>
#include <DiskDeviceVisitor.h>
#include <LayoutBuilder.h>
#include <Messenger.h>
#include <Partition.h>
#include <Path.h>
#include <Roster.h>
#include <String.h>
#include <TextControl.h>
#include <TextView.h>
#include <Window.h>
#include <fs_volume.h>

#include <encrypted_home_driver.h>
#include <encrypted_volume_header.h>
#include <openssl/crypto.h>
#include <ServerProtocol.h>
#include <secure_buffer.h>
#include <settings_format.h>

#include <syscalls.h>

#pragma GCC diagnostic pop


#undef B_TRANSLATION_CONTEXT
#define B_TRANSLATION_CONTEXT "UnlockVolume"


namespace {

using namespace BPrivate::EncryptedHome;
using namespace BPrivate::EncryptedHome::Unlock;

constexpr size_t kMaxPassphraseLength = 1024;
constexpr status_t kOk = 0;

constexpr uint32
MessageCode(char a, char b, char c, char d)
{
	return (static_cast<uint32>(static_cast<unsigned char>(a)) << 24)
		| (static_cast<uint32>(static_cast<unsigned char>(b)) << 16)
		| (static_cast<uint32>(static_cast<unsigned char>(c)) << 8)
		| static_cast<uint32>(static_cast<unsigned char>(d));
}

constexpr uint32 kMsgUnlock = MessageCode('u', 'n', 'l', 'k');
constexpr uint32 kMsgCancel = MessageCode('c', 'n', 'c', 'l');


void
NotifyHomeSettingsReloaded()
{
	BMessenger appServer("application/x-vnd.Haiku-app_server");
	if (appServer.IsValid())
		appServer.SendMessage(AS_HOME_SETTINGS_RELOADED);
}


struct CandidateVolume {
	BPath path;
	dev_t device = -1;
	uint32 sectorSize = 0;
	uint64 payloadSizeSectors = 0;
	EncryptedVolumeHeader::HeaderPair headers = {};
};


std::expected<void, status_t>
ReadAt(const char* path, uint64 offset, std::span<std::byte> buffer)
{
	std::FILE* file = std::fopen(path, "rb");
	if (file == NULL)
		return std::unexpected(errno == 0 ? B_ENTRY_NOT_FOUND : errno);
	if (fseeko(file, static_cast<off_t>(offset), SEEK_SET) != 0) {
		status_t status = errno == 0 ? B_IO_ERROR : errno;
		std::fclose(file);
		return std::unexpected(status);
	}
	if (std::fread(buffer.data(), 1, buffer.size(), file) != buffer.size()) {
		std::fclose(file);
		return std::unexpected(B_IO_ERROR);
	}
	std::fclose(file);
	return {};
}


bool
SameUuid(const std::array<std::byte, 16>& left,
	const std::array<std::byte, 16>& right)
{
	return std::equal(left.begin(), left.end(), right.begin(), right.end());
}


std::expected<CandidateVolume, status_t>
ProbePartition(BPartition& partition, const EncryptedHomeSettings& settings)
{
	if (partition.IsMounted() || partition.CountChildren() > 0)
		return std::unexpected(B_BAD_VALUE);

	CandidateVolume candidate;
	status_t status = partition.GetPath(&candidate.path);
	if (status != kOk)
		return std::unexpected(status);
	candidate.sectorSize = partition.BlockSize();

	if (auto result = ReadAt(candidate.path.Path(), 0, candidate.headers.primary);
			!result.has_value()) {
		return std::unexpected(result.error());
	}

	auto primary = EncryptedVolumeHeader::Parse(candidate.headers.primary);
	if (primary.has_value()
		&& SameUuid(primary->volumeUuid, settings.volumeUuid)) {
		candidate.sectorSize = primary->sectorSize;
		candidate.payloadSizeSectors = primary->payloadSizeSectors;
		const uint64 backupOffset = static_cast<uint64>(primary->sectorSize) * 8;
		if (auto result = ReadAt(candidate.path.Path(), backupOffset,
				candidate.headers.backup); !result.has_value())
			candidate.headers.backup = {};
	} else {
		bool found = false;
		for (const uint32 sectorSize : {uint32{4096}, uint32{512}}) {
			HeaderBytes backup = {};
			if (auto result = ReadAt(candidate.path.Path(),
					static_cast<uint64>(sectorSize) * 8, backup);
					!result.has_value()) {
				continue;
			}
			auto parsed = EncryptedVolumeHeader::Parse(backup);
			if (parsed.has_value() && parsed->sectorSize == sectorSize
				&& SameUuid(parsed->volumeUuid, settings.volumeUuid)) {
				candidate.headers.backup = backup;
				candidate.sectorSize = sectorSize;
				candidate.payloadSizeSectors = parsed->payloadSizeSectors;
				found = true;
				break;
			}
		}
		if (!found)
			return std::unexpected(B_NAME_NOT_FOUND);
	}

	struct stat stat;
	if (::stat(candidate.path.Path(), &stat) != 0)
		return std::unexpected(errno == 0 ? B_IO_ERROR : errno);
	candidate.device = S_ISREG(stat.st_mode) ? stat.st_dev : stat.st_rdev;
	return candidate;
}


class CandidateVisitor : public BDiskDeviceVisitor {
public:
	using BDiskDeviceVisitor::Visit;

	CandidateVisitor(const EncryptedHomeSettings& settings,
		CandidateVolume& candidate)
		:
		fSettings(settings),
		fCandidate(candidate)
	{
	}

	bool Visit(BPartition* partition, int32 level) override
	{
		(void)level;
		if (partition == NULL)
			return false;

		auto candidate = ProbePartition(*partition, fSettings);
		if (!candidate.has_value())
			return false;

		fCandidate = std::move(*candidate);
		fFound = true;
		return true;
	}

	bool Found() const
	{
		return fFound;
	}

private:
	const EncryptedHomeSettings& fSettings;
	CandidateVolume& fCandidate;
	bool fFound = false;
};


std::expected<CandidateVolume, status_t>
FindCandidate(const EncryptedHomeSettings& settings)
{
	BDiskDeviceRoster roster;
	CandidateVolume candidate;
	CandidateVisitor visitor(settings, candidate);
	roster.VisitEachPartition(&visitor);
	if (visitor.Found())
		return candidate;
	return std::unexpected(B_NAME_NOT_FOUND);
}


std::expected<void, status_t>
RegisterAndUnlock(const CandidateVolume& candidate,
	UnlockedHeader& unlocked)
{
	BString controlPath("/dev/");
	controlPath << ENCRYPTED_HOME_CONTROL_DEVICE_NAME;
	int control = open(controlPath.String(), O_RDWR);
	if (control < 0)
		return std::unexpected(errno == 0 ? B_ENTRY_NOT_FOUND : errno);

	encrypted_home_ioctl_register registration = {};
	registration.backingDevice = candidate.device;
	registration.sectorSize = candidate.sectorSize;
	registration.payloadSizeSectors = candidate.payloadSizeSectors;
	strlcpy(registration.backingPath, candidate.path.Path(),
		sizeof(registration.backingPath));
	if (ioctl(control, IOCTL_ENCRYPTED_HOME_REGISTER, &registration,
			sizeof(registration)) != 0) {
		status_t status = errno == 0 ? B_IO_ERROR : errno;
		close(control);
		return std::unexpected(status);
	}
	close(control);

	auto unregisterDevice = [&controlPath, &registration]() {
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
		status_t status = errno == 0 ? B_ENTRY_NOT_FOUND : errno;
		unregisterDevice();
		return std::unexpected(status);
	}

	encrypted_home_ioctl_unlock unlockRequest = {};
	unlockRequest.cipherId = unlocked.cipherId;
	unlockRequest.masterKeyLength = unlocked.masterKeyLength;
	std::memcpy(unlockRequest.masterKey, unlocked.masterKey.data(),
		unlocked.masterKeyLength);
	if (ioctl(raw, IOCTL_ENCRYPTED_HOME_UNLOCK, &unlockRequest,
			sizeof(unlockRequest)) != 0) {
		status_t status = errno == 0 ? B_IO_ERROR : errno;
		OPENSSL_cleanse(&unlockRequest, sizeof(unlockRequest));
		close(raw);
		unregisterDevice();
		return std::unexpected(status);
	}
	OPENSSL_cleanse(&unlockRequest, sizeof(unlockRequest));
	close(raw);

	dev_t mounted = fs_mount_volume("/boot/home", rawPath.String(), "bfs", 0,
		NULL);
	if (mounted < 0) {
		unregisterDevice();
		return std::unexpected(static_cast<status_t>(mounted));
	}

	NotifyHomeSettingsReloaded();
	return {};
}


std::expected<void, status_t>
UnlockEncryptedHome(const EncryptedHomeSettings& settings,
	std::span<const std::byte> passphrase)
{
	auto candidate = FindCandidate(settings);
	if (!candidate.has_value())
		return std::unexpected(candidate.error());

	auto unlocked = EncryptedVolumeHeader::Open(candidate->headers, passphrase);
	if (!unlocked.has_value())
		return std::unexpected(unlocked.error());
	return RegisterAndUnlock(*candidate, *unlocked);
}


class UnlockWindow : public BWindow {
public:
	UnlockWindow(EncryptedHomeSettings settings, int32& exitStatus)
		:
		BWindow(BRect(100, 100, 460, 220), B_TRANSLATE("Unlock home"),
			B_TITLED_WINDOW, B_NOT_RESIZABLE | B_NOT_ZOOMABLE
				| B_AUTO_UPDATE_SIZE_LIMITS),
		fSettings(settings),
		fExitStatus(exitStatus)
	{
		fPassphrase = new BTextControl("passphrase",
			B_TRANSLATE("Passphrase:"), "", new BMessage(kMsgUnlock));
		fPassphrase->TextView()->HideTyping(true);
		fUnlock = new BButton("unlock", B_TRANSLATE("Unlock"),
			new BMessage(kMsgUnlock));

		BLayoutBuilder::Group<>(this, B_VERTICAL, B_USE_DEFAULT_SPACING)
			.SetInsets(B_USE_WINDOW_INSETS)
			.Add(fPassphrase)
			.AddGroup(B_HORIZONTAL)
				.AddGlue()
				.Add(new BButton("cancel", B_TRANSLATE("Cancel"),
					new BMessage(kMsgCancel)))
				.Add(fUnlock)
			.End();

		fPassphrase->MakeFocus(true);
	}

	void MessageReceived(BMessage* message) override
	{
		switch (message->what) {
			case kMsgUnlock:
				_AttemptUnlock();
				break;
			case kMsgCancel:
				fExitStatus = 1;
				be_app->PostMessage(B_QUIT_REQUESTED);
				break;
			default:
				BWindow::MessageReceived(message);
				break;
		}
	}

	bool QuitRequested() override
	{
		if (!fUnlockSucceeded)
			fExitStatus = 1;
		be_app->PostMessage(B_QUIT_REQUESTED);
		return true;
	}

private:
	void _AttemptUnlock()
	{
		secure_buffer<kMaxPassphraseLength> passphrase;
		const char* text = fPassphrase->Text();
		const size_t length = std::min(std::strlen(text), passphrase.size());
		std::memcpy(passphrase.data(), text, length);
		fPassphrase->SetText("");

		auto result = UnlockEncryptedHome(fSettings,
			{passphrase.data(), length});
		if (result.has_value()) {
			fExitStatus = 0;
			fUnlockSucceeded = true;
			be_app->PostMessage(B_QUIT_REQUESTED);
			return;
		}

		fFailures++;
		if (fFailures < 3) {
			BAlert* alert = new BAlert("unlock failed",
				B_TRANSLATE("The home volume could not be unlocked."),
				B_TRANSLATE("Try again"), NULL, NULL, B_WIDTH_AS_USUAL,
				B_WARNING_ALERT);
			alert->Go();
			return;
		}

		BAlert* alert = new BAlert("unlock failed",
			B_TRANSLATE("The home volume could not be unlocked."),
			B_TRANSLATE("Continue without home folder"),
			B_TRANSLATE("Reboot"), NULL, B_WIDTH_AS_USUAL, B_STOP_ALERT);
		const int32 choice = alert->Go();
		if (choice == 1)
			_kern_shutdown(true);
		else {
			entry_ref terminal;
			if (get_ref_for_path("/system/apps/Terminal", &terminal) == kOk)
				be_roster->Launch(&terminal);
			fExitStatus = 0;
			fUnlockSucceeded = true;
			be_app->PostMessage(B_QUIT_REQUESTED);
		}
	}

	EncryptedHomeSettings fSettings;
	int32& fExitStatus;
	BTextControl* fPassphrase = NULL;
	BButton* fUnlock = NULL;
	int32 fFailures = 0;
	bool fUnlockSucceeded = false;
};


class UnlockVolumeApp : public BApplication {
public:
	UnlockVolumeApp()
		:
		BApplication("application/x-vnd.Haiku-unlock_volume")
	{
	}

	void ReadyToRun() override
	{
		EncryptedHomeSettings encryptedHomeSettings;
		status_t status = ReadSettingsFile(settings::kBootSettingsPath,
			encryptedHomeSettings);
		if (!SettingsRequireUnlock(status, encryptedHomeSettings)) {
			fExitStatus = status == kOk || status == B_ENTRY_NOT_FOUND
				? 0 : status;
			if (fExitStatus == 0)
				NotifyHomeSettingsReloaded();
			PostMessage(B_QUIT_REQUESTED);
			return;
		}

		if (const char* scripted = std::getenv("HAIKU_UNLOCK_VOLUME_PASSPHRASE")) {
			auto result = UnlockEncryptedHome(encryptedHomeSettings,
				PassphraseBytes(scripted));
			fExitStatus = result.has_value() ? 0 : result.error();
			PostMessage(B_QUIT_REQUESTED);
			return;
		}

		UnlockWindow* window = new UnlockWindow(encryptedHomeSettings, fExitStatus);
		window->Show();
	}

	int32 ExitStatus() const
	{
		return fExitStatus;
	}

private:
	int32 fExitStatus = 0;
};

} // namespace


int
main()
{
	UnlockVolumeApp app;
	app.Run();
	return app.ExitStatus();
}
