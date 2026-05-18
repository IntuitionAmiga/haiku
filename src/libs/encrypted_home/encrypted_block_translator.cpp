/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <encrypted_block_translator.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <memory>
#include <limits>
#include <utility>
#include <vector>

#include <sys/types.h>

#include <Errors.h>
#include <xts_haiku_shim.h>


namespace BPrivate::EncryptedHome {
namespace {

constexpr uint64 kHeaderSectorCount = 16;
constexpr uint64 kBackupHeaderSector = 8;
constexpr size_t kZeroPayloadChunkBytes = 1024 * 1024;


bool
RangeFits(uint64 offset, size_t length, uint64 totalSize)
{
	return offset <= totalSize && length <= totalSize - offset;
}


std::expected<uint64, status_t>
BackingOffsetForPayload(uint32 sectorSize, uint64 payloadOffset,
	size_t length)
{
	const uint64 headerBytes = kHeaderSectorCount * sectorSize;
	if (payloadOffset > UINT64_MAX - headerBytes)
		return std::unexpected(B_BAD_VALUE);

	const uint64 backingOffset = headerBytes + payloadOffset;
	if (length > UINT64_MAX - backingOffset)
		return std::unexpected(B_BAD_VALUE);

	return backingOffset;
}


std::expected<uint64, status_t>
PayloadSizeBytes(uint64 payloadSizeSectors, uint32 sectorSize)
{
	if (payloadSizeSectors > UINT64_MAX / sectorSize)
		return std::unexpected(B_BAD_VALUE);
	return payloadSizeSectors * sectorSize;
}


bool
IsAligned(uint64 offset, size_t length, uint32 sectorSize)
{
	return sectorSize != 0 && (offset % sectorSize) == 0
		&& (length % sectorSize) == 0;
}


std::expected<void, status_t>
ReadHeaderPair(BackingStore& store, uint32 sectorSize,
	EncryptedVolumeHeader::HeaderPair& pair)
{
	if (auto result = store.ReadAt(0, pair.primary); !result.has_value())
		return std::unexpected(result.error());

	const uint64 backupOffset = kBackupHeaderSector * sectorSize;
	if (auto result = store.ReadAt(backupOffset, pair.backup);
			!result.has_value()) {
		return std::unexpected(result.error());
	}

	return {};
}


std::expected<void, status_t>
WriteHeaderPair(BackingStore& store, uint32 sectorSize,
	const HeaderBytes& header)
{
	const uint64 backupOffset = kBackupHeaderSector * sectorSize;
	if (auto result = store.WriteAt(backupOffset, header);
			!result.has_value()) {
		return std::unexpected(result.error());
	}
	if (auto result = store.WriteAt(0, header); !result.has_value())
		return std::unexpected(result.error());
	if (auto result = store.Flush(); !result.has_value())
		return std::unexpected(result.error());

	return {};
}


std::expected<void, status_t>
ClearAlternateBackupHeader(BackingStore& store, uint32 sectorSize,
	uint64 payloadSizeSectors)
{
	const uint32 alternateSectorSize = sectorSize == 512 ? 4096 : 512;
	const uint64 alternateOffset = kBackupHeaderSector * alternateSectorSize;
	const uint64 volumeSectors = kHeaderSectorCount + payloadSizeSectors;
	if (volumeSectors > UINT64_MAX / sectorSize)
		return std::unexpected(B_BAD_VALUE);

	const uint64 volumeBytes = volumeSectors * sectorSize;
	if (alternateOffset > volumeBytes
		|| HeaderBytes{}.size() > volumeBytes - alternateOffset) {
		return {};
	}

	HeaderBytes existing = {};
	const auto read = store.ReadAt(alternateOffset, existing);
	if (!read.has_value() && read.error() == B_BAD_VALUE)
		return {};
	if (!read.has_value())
		return std::unexpected(read.error());

	HeaderBytes zeroed = {};
	const auto result = store.WriteAt(alternateOffset, zeroed);
	if (!result.has_value() && result.error() != B_BAD_VALUE)
		return std::unexpected(result.error());

	return {};
}


std::expected<void, status_t>
WriteEncryptedZeroPayload(BackingStore& store, xts_haiku_context& context,
	uint32 sectorSize, uint64 payloadSizeSectors)
{
	const uint64 sectorsPerChunk = std::max<uint64>(1,
		kZeroPayloadChunkBytes / sectorSize);
	std::vector<std::byte> chunk(static_cast<size_t>(sectorsPerChunk)
		* sectorSize);
	const uint64 payloadOffset = kHeaderSectorCount * sectorSize;

	for (uint64 sectorIndex = 0; sectorIndex < payloadSizeSectors;) {
		const uint64 sectorsThisChunk = std::min(sectorsPerChunk,
			payloadSizeSectors - sectorIndex);
		const size_t bytesThisChunk = static_cast<size_t>(sectorsThisChunk)
			* sectorSize;
		std::span<std::byte> encrypted = std::span(chunk).first(
			bytesThisChunk);
		std::fill(encrypted.begin(), encrypted.end(), std::byte{0});

		for (uint64 chunkSector = 0; chunkSector < sectorsThisChunk;
				chunkSector++) {
			std::span<std::byte> sector = encrypted.subspan(
				static_cast<size_t>(chunkSector) * sectorSize, sectorSize);
			if (xts_haiku_crypt(&context, sectorIndex + chunkSector, nullptr,
					reinterpret_cast<uint8_t*>(sector.data()),
					sector.size(), true) != 0) {
				return std::unexpected(B_ERROR);
			}
		}

		if (auto result = store.WriteAt(payloadOffset
				+ sectorIndex * sectorSize, encrypted); !result.has_value()) {
			return std::unexpected(result.error());
		}
		sectorIndex += sectorsThisChunk;
	}

	return store.Flush();
}


std::expected<uint32, status_t>
DetectSectorSize(BackingStore& store, std::span<const std::byte> passphrase)
{
	HeaderBytes primary = {};
	if (auto result = store.ReadAt(0, primary); !result.has_value())
		return std::unexpected(result.error());

	status_t permissionError = 0;
	uint32 authenticatedPrimarySectorSize = 0;

	const auto primaryUnlocked = EncryptedVolumeHeader::Unlock(primary,
		passphrase);
	if (primaryUnlocked.has_value()) {
		const auto primaryParsed = EncryptedVolumeHeader::Parse(primary);
		if (!primaryParsed.has_value())
			return std::unexpected(primaryParsed.error());
		authenticatedPrimarySectorSize = primaryParsed->sectorSize;
	} else if (primaryUnlocked.error() == B_PERMISSION_DENIED) {
		permissionError = B_PERMISSION_DENIED;
	}

	if (authenticatedPrimarySectorSize != 0)
		return authenticatedPrimarySectorSize;

	uint32 authenticatedBackupSectorSize = 0;
	HeaderBytes authenticatedBackup = {};
	bool currentBackupDeniedPassphrase = false;
	for (uint32 sectorSize : {uint32{4096}, uint32{512}}) {
		HeaderBytes backup = {};

		if (auto result = store.ReadAt(kBackupHeaderSector * sectorSize,
				backup); !result.has_value()) {
			continue;
		}

		const auto backupUnlocked = EncryptedVolumeHeader::Unlock(backup,
			passphrase);
		if (backupUnlocked.has_value()) {
			const auto backupParsed = EncryptedVolumeHeader::Parse(backup);
			if (!backupParsed.has_value())
				return std::unexpected(backupParsed.error());
			if (backupParsed->sectorSize != sectorSize)
				continue;
			if (authenticatedBackupSectorSize != 0
				&& backup != authenticatedBackup) {
				return std::unexpected(B_BAD_DATA);
			}
			authenticatedBackupSectorSize = backupParsed->sectorSize;
			authenticatedBackup = backup;
			continue;
		}
		if (backupUnlocked.error() == B_PERMISSION_DENIED) {
			permissionError = B_PERMISSION_DENIED;
			const auto backupParsed = EncryptedVolumeHeader::Parse(backup);
			if (backupParsed.has_value() && backupParsed->sectorSize == sectorSize)
				currentBackupDeniedPassphrase = true;
		}
	}

	if (authenticatedBackupSectorSize != 0) {
		if (currentBackupDeniedPassphrase)
			return std::unexpected(B_PERMISSION_DENIED);
		return authenticatedBackupSectorSize;
	}

	if (permissionError != 0)
		return std::unexpected(permissionError);
	return std::unexpected(B_BAD_DATA);
}


status_t
ErrnoStatus()
{
	return errno == 0 ? B_ERROR : errno;
}


std::expected<ParsedHeader, status_t>
ParseFirstAuthenticatedHeader(const EncryptedVolumeHeader::HeaderPair& pair,
	std::span<const std::byte> passphrase)
{
	const auto primaryUnlocked = EncryptedVolumeHeader::Unlock(pair.primary,
		passphrase);
	if (primaryUnlocked.has_value())
		return EncryptedVolumeHeader::Parse(pair.primary);

	const auto backupUnlocked = EncryptedVolumeHeader::Unlock(pair.backup,
		passphrase);
	if (backupUnlocked.has_value())
		return EncryptedVolumeHeader::Parse(pair.backup);

	if (primaryUnlocked.error() == B_PERMISSION_DENIED
		|| backupUnlocked.error() == B_PERMISSION_DENIED) {
		return std::unexpected(B_PERMISSION_DENIED);
	}

	return std::unexpected(B_BAD_DATA);
}

} // namespace


std::expected<void, status_t>
BackingStore::Flush()
{
	return {};
}


FileBackingStore::FileBackingStore(std::FILE* file)
	:
	fFile(file)
{
}


std::expected<void, status_t>
FileBackingStore::ReadAt(uint64 offset, std::span<std::byte> buffer)
{
	if (fFile == nullptr
		|| offset > static_cast<uint64>(std::numeric_limits<off_t>::max())) {
		return std::unexpected(B_BAD_VALUE);
	}

	errno = 0;
	if (::fseeko(fFile, static_cast<off_t>(offset), SEEK_SET) != 0)
		return std::unexpected(ErrnoStatus());
	if (std::fread(buffer.data(), 1, buffer.size(), fFile) != buffer.size())
		return std::unexpected(std::ferror(fFile) != 0 ? ErrnoStatus()
			: B_BAD_VALUE);

	return {};
}


std::expected<void, status_t>
FileBackingStore::WriteAt(uint64 offset, std::span<const std::byte> buffer)
{
	if (fFile == nullptr
		|| offset > static_cast<uint64>(std::numeric_limits<off_t>::max())) {
		return std::unexpected(B_BAD_VALUE);
	}

	errno = 0;
	if (::fseeko(fFile, static_cast<off_t>(offset), SEEK_SET) != 0)
		return std::unexpected(ErrnoStatus());
	if (std::fwrite(buffer.data(), 1, buffer.size(), fFile) != buffer.size())
		return std::unexpected(ErrnoStatus());

	return {};
}


std::expected<void, status_t>
FileBackingStore::Flush()
{
	if (fFile == nullptr)
		return std::unexpected(B_BAD_VALUE);

	errno = 0;
	if (std::fflush(fFile) != 0)
		return std::unexpected(ErrnoStatus());
	return {};
}


EncryptedBlockTranslator::EncryptedBlockTranslator() = default;


EncryptedBlockTranslator::EncryptedBlockTranslator(
	EncryptedBlockTranslator&& other) noexcept
	:
	fStore(other.fStore),
	fSectorSize(other.fSectorSize),
	fPayloadSizeSectors(other.fPayloadSizeSectors),
	fPayloadSizeBytes(other.fPayloadSizeBytes),
	fCipherId(other.fCipherId),
	fMasterKey(std::move(other.fMasterKey)),
	fMasterKeyLength(other.fMasterKeyLength),
	fXts(other.fXts),
	fOpen(other.fOpen)
{
	other.fStore = nullptr;
	other.fSectorSize = 0;
	other.fPayloadSizeSectors = 0;
	other.fPayloadSizeBytes = 0;
	other.fCipherId = 0;
	other.fMasterKeyLength = 0;
	other.fXts = nullptr;
	other.fOpen = false;
}


EncryptedBlockTranslator&
EncryptedBlockTranslator::operator=(EncryptedBlockTranslator&& other) noexcept
{
	if (this != &other) {
		(void)Close();
		fStore = other.fStore;
		fSectorSize = other.fSectorSize;
		fPayloadSizeSectors = other.fPayloadSizeSectors;
		fPayloadSizeBytes = other.fPayloadSizeBytes;
		fCipherId = other.fCipherId;
		fMasterKey = std::move(other.fMasterKey);
		fMasterKeyLength = other.fMasterKeyLength;
		fXts = other.fXts;
		fOpen = other.fOpen;

		other.fStore = nullptr;
		other.fSectorSize = 0;
		other.fPayloadSizeSectors = 0;
		other.fPayloadSizeBytes = 0;
		other.fCipherId = 0;
		other.fMasterKeyLength = 0;
		other.fXts = nullptr;
		other.fOpen = false;
	}
	return *this;
}


EncryptedBlockTranslator::~EncryptedBlockTranslator()
{
	(void)Close();
}


std::expected<EncryptedBlockTranslator, status_t>
EncryptedBlockTranslator::Format(BackingStore& store,
	std::span<const std::byte> passphrase, const FormatOptions& options)
{
	auto formatted = EncryptedVolumeHeader::Format(passphrase, options);
	if (!formatted.has_value())
		return std::unexpected(formatted.error());

	if (auto result = WriteHeaderPair(store, options.sectorSize,
			formatted->header); !result.has_value()) {
		return std::unexpected(result.error());
	}

	const auto parsed = EncryptedVolumeHeader::Parse(formatted->header);
	if (!parsed.has_value())
		return std::unexpected(parsed.error());

	UnlockedHeader unlocked;
	unlocked.cipherId = parsed->cipherId;
	unlocked.masterKey = std::move(formatted->masterKey);
	unlocked.masterKeyLength = formatted->masterKeyLength;
	auto translator = FromUnlocked(store, std::move(unlocked), *parsed);
	if (!translator.has_value())
		return std::unexpected(translator.error());

	if (auto result = ClearAlternateBackupHeader(store, options.sectorSize,
			options.payloadSizeSectors); !result.has_value()) {
		return std::unexpected(result.error());
	}

	if (auto result = WriteEncryptedZeroPayload(store, *translator->fXts,
			translator->fSectorSize, translator->fPayloadSizeSectors);
			!result.has_value()) {
		return std::unexpected(result.error());
	}

	return translator;
}


std::expected<EncryptedBlockTranslator, status_t>
EncryptedBlockTranslator::Open(BackingStore& store,
	std::span<const std::byte> passphrase)
{
	const auto sectorSize = DetectSectorSize(store, passphrase);
	if (!sectorSize.has_value())
		return std::unexpected(sectorSize.error());

	EncryptedVolumeHeader::HeaderPair pair;
	if (auto result = ReadHeaderPair(store, *sectorSize, pair);
			!result.has_value()) {
		return std::unexpected(result.error());
	}
	const EncryptedVolumeHeader::HeaderPair originalPair = pair;

	auto unlocked = EncryptedVolumeHeader::Open(pair, passphrase);
	if (!unlocked.has_value())
		return std::unexpected(unlocked.error());

	const auto parsed = ParseFirstAuthenticatedHeader(pair, passphrase);
	if (!parsed.has_value())
		return std::unexpected(parsed.error());

	if (pair.primary != originalPair.primary
		|| pair.backup != originalPair.backup) {
		if (auto result = WriteHeaderPair(store, parsed->sectorSize,
				pair.primary); !result.has_value()) {
			return std::unexpected(result.error());
		}
	}

	return FromUnlocked(store, std::move(*unlocked), *parsed);
}


std::expected<EncryptedBlockTranslator, status_t>
EncryptedBlockTranslator::FromUnlocked(BackingStore& store,
	UnlockedHeader&& unlocked, const ParsedHeader& parsed)
{
	EncryptedBlockTranslator translator;
	translator.fStore = &store;
	translator.fSectorSize = parsed.sectorSize;
	translator.fPayloadSizeSectors = parsed.payloadSizeSectors;
	const auto payloadSizeBytes = PayloadSizeBytes(parsed.payloadSizeSectors,
		parsed.sectorSize);
	if (!payloadSizeBytes.has_value())
		return std::unexpected(payloadSizeBytes.error());
	translator.fPayloadSizeBytes = *payloadSizeBytes;
	translator.fCipherId = parsed.cipherId;
	translator.fMasterKeyLength = unlocked.masterKeyLength;
	translator.fMasterKey = std::move(unlocked.masterKey);
	translator.fXts = new (std::nothrow) xts_haiku_context;
	if (translator.fXts == nullptr)
		return std::unexpected(B_NO_MEMORY);

	if (xts_haiku_init(translator.fXts,
			reinterpret_cast<const uint8_t*>(translator.fMasterKey.data()),
			translator.fMasterKeyLength) != 0) {
		return std::unexpected(B_ERROR);
	}

	translator.fOpen = true;
	return translator;
}


std::expected<void, status_t>
EncryptedBlockTranslator::ReadAt(uint64 offset, std::span<std::byte> buffer)
{
	if (!fOpen || fStore == nullptr || fXts == nullptr)
		return std::unexpected(B_BAD_VALUE);
	if (!IsAligned(offset, buffer.size(), fSectorSize))
		return std::unexpected(B_BAD_VALUE);
	if (!RangeFits(offset, buffer.size(), PayloadSize()))
		return std::unexpected(B_BAD_VALUE);

	const auto backingOffset = BackingOffsetForPayload(fSectorSize, offset,
		buffer.size());
	if (!backingOffset.has_value())
		return std::unexpected(backingOffset.error());

	if (auto result = fStore->ReadAt(*backingOffset, buffer);
			!result.has_value()) {
		return std::unexpected(result.error());
	}

	const uint64 firstSector = offset / fSectorSize;
	const size_t sectors = buffer.size() / fSectorSize;
	for (size_t i = 0; i < sectors; i++) {
		if (xts_haiku_crypt(fXts, firstSector + i, nullptr,
				reinterpret_cast<uint8_t*>(buffer.data() + i * fSectorSize),
				fSectorSize, false) != 0) {
			return std::unexpected(B_ERROR);
		}
	}

	return {};
}


std::expected<void, status_t>
EncryptedBlockTranslator::WriteAt(uint64 offset,
	std::span<const std::byte> buffer)
{
	if (!fOpen || fStore == nullptr || fXts == nullptr)
		return std::unexpected(B_BAD_VALUE);
	if (!IsAligned(offset, buffer.size(), fSectorSize))
		return std::unexpected(B_BAD_VALUE);
	if (!RangeFits(offset, buffer.size(), PayloadSize()))
		return std::unexpected(B_BAD_VALUE);

	std::vector<std::byte> encrypted(buffer.begin(), buffer.end());
	const uint64 firstSector = offset / fSectorSize;
	const size_t sectors = encrypted.size() / fSectorSize;
	for (size_t i = 0; i < sectors; i++) {
		if (xts_haiku_crypt(fXts, firstSector + i, nullptr,
				reinterpret_cast<uint8_t*>(encrypted.data()
					+ i * fSectorSize), fSectorSize, true) != 0) {
			return std::unexpected(B_ERROR);
		}
	}

	const auto backingOffset = BackingOffsetForPayload(fSectorSize, offset,
		encrypted.size());
	if (!backingOffset.has_value())
		return std::unexpected(backingOffset.error());

	if (auto result = fStore->WriteAt(*backingOffset, encrypted);
			!result.has_value()) {
		return std::unexpected(result.error());
	}

	return {};
}


std::expected<void, status_t>
EncryptedBlockTranslator::Close()
{
	status_t flushStatus = 0;
	if (fOpen && fStore != nullptr) {
		if (auto result = fStore->Flush(); !result.has_value())
			flushStatus = result.error();
	}

	if (fXts != nullptr) {
		xts_haiku_clear(fXts);
		delete fXts;
		fXts = nullptr;
	}

	fMasterKey.Cleanse();
	fStore = nullptr;
	fSectorSize = 0;
	fPayloadSizeSectors = 0;
	fPayloadSizeBytes = 0;
	fCipherId = 0;
	fMasterKeyLength = 0;
	fOpen = false;
	if (flushStatus != 0)
		return std::unexpected(flushStatus);
	return {};
}


uint64
EncryptedBlockTranslator::PayloadSize() const
{
	return fPayloadSizeBytes;
}

} // namespace BPrivate::EncryptedHome
