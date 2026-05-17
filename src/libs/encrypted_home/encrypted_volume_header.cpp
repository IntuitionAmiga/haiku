/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <encrypted_volume_header.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>

#include <argon2.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <Errors.h>


namespace BPrivate::EncryptedHome {
namespace {

constexpr uint32 kMaxArgon2TimeCost = wire::kMaxArgon2TimeCost;
constexpr uint32 kMaxArgon2MemoryCostKiB = wire::kMaxArgon2MemoryCostKiB;
constexpr uint32 kMaxArgon2Parallelism = wire::kMaxArgon2Parallelism;

std::array<std::byte, 64> sLastDerivedBuffer = {};


uint16
ReadLE16(std::span<const std::byte> bytes, size_t offset)
{
	return static_cast<uint16>(std::to_integer<uint16>(bytes[offset]))
		| static_cast<uint16>(std::to_integer<uint16>(bytes[offset + 1]) << 8);
}


uint32
ReadLE32(std::span<const std::byte> bytes, size_t offset)
{
	return static_cast<uint32>(std::to_integer<uint32>(bytes[offset]))
		| (static_cast<uint32>(std::to_integer<uint32>(bytes[offset + 1])) << 8)
		| (static_cast<uint32>(std::to_integer<uint32>(bytes[offset + 2])) << 16)
		| (static_cast<uint32>(std::to_integer<uint32>(bytes[offset + 3])) << 24);
}


uint64
ReadLE64(std::span<const std::byte> bytes, size_t offset)
{
	return static_cast<uint64>(ReadLE32(bytes, offset))
		| (static_cast<uint64>(ReadLE32(bytes, offset + 4)) << 32);
}


void
WriteLE16(HeaderBytes& bytes, size_t offset, uint16 value)
{
	bytes[offset] = std::byte(value & 0xff);
	bytes[offset + 1] = std::byte((value >> 8) & 0xff);
}


void
WriteLE32(HeaderBytes& bytes, size_t offset, uint32 value)
{
	bytes[offset] = std::byte(value & 0xff);
	bytes[offset + 1] = std::byte((value >> 8) & 0xff);
	bytes[offset + 2] = std::byte((value >> 16) & 0xff);
	bytes[offset + 3] = std::byte((value >> 24) & 0xff);
}


void
WriteLE64(HeaderBytes& bytes, size_t offset, uint64 value)
{
	WriteLE32(bytes, offset, static_cast<uint32>(value & 0xffffffffu));
	WriteLE32(bytes, offset + 4, static_cast<uint32>(value >> 32));
}


bool
AllZero(std::span<const std::byte> bytes)
{
	return std::all_of(bytes.begin(), bytes.end(),
		[](std::byte byte) { return byte == std::byte{0}; });
}


uint32
MasterKeyLength(uint32 cipherId)
{
	switch (cipherId) {
		case kCipherAES128XTS:
			return 32;
		case kCipherAES256XTS:
			return 64;
		default:
			return 0;
	}
}


bool
KdfParametersAreBounded(uint32 timeCost, uint32 memoryCostKiB,
	uint32 parallelism)
{
	return timeCost > 0 && timeCost <= kMaxArgon2TimeCost
		&& memoryCostKiB > 0 && memoryCostKiB <= kMaxArgon2MemoryCostKiB
		&& parallelism > 0 && parallelism <= kMaxArgon2Parallelism
		&& memoryCostKiB >= parallelism * 8;
}


std::expected<void, status_t>
FillRandom(std::span<std::byte> bytes)
{
	if (bytes.size() > 0x7fffffffu)
		return std::unexpected(B_BAD_VALUE);

	if (RAND_bytes(reinterpret_cast<unsigned char*>(bytes.data()),
			static_cast<int>(bytes.size())) != 1) {
		return std::unexpected(B_ERROR);
	}

	return {};
}


std::expected<secure_buffer<64>, status_t>
DeriveKey(std::span<const std::byte> passphrase,
	std::span<const std::byte, 32> salt, uint32 timeCost,
	uint32 memoryCostKiB, uint32 parallelism)
{
	secure_buffer<64> derived;
	const int result = argon2id_hash_raw(timeCost, memoryCostKiB, parallelism,
		passphrase.data(), passphrase.size(), salt.data(), salt.size(),
		derived.data(), derived.size());
	if (result != ARGON2_OK)
		return std::unexpected(B_ERROR);

	return derived;
}


void
RecordDerivedAfterCleanse(secure_buffer<64>& derived)
{
	derived.Cleanse();
	std::copy(derived.data(), derived.data() + derived.size(),
		sLastDerivedBuffer.begin());
}


std::expected<void, status_t>
ComputeHmac(HeaderBytes& header, std::span<const std::byte, 32> macKey)
{
	unsigned int hmacLength = 0;
	unsigned char* result = HMAC(EVP_sha256(), macKey.data(),
		static_cast<int>(macKey.size()),
		reinterpret_cast<const unsigned char*>(header.data()),
		wire::kHmacCoveredEnd,
		reinterpret_cast<unsigned char*>(header.data() + wire::kHeaderHmacOffset),
		&hmacLength);
	if (result == nullptr || hmacLength != 32)
		return std::unexpected(B_ERROR);

	return {};
}


std::expected<void, status_t>
VerifyHmac(const HeaderBytes& header, std::span<const std::byte, 32> macKey)
{
	std::array<std::byte, 32> expected = {};
	unsigned int hmacLength = 0;
	unsigned char* result = HMAC(EVP_sha256(), macKey.data(),
		static_cast<int>(macKey.size()),
		reinterpret_cast<const unsigned char*>(header.data()),
		wire::kHmacCoveredEnd,
		reinterpret_cast<unsigned char*>(expected.data()), &hmacLength);
	if (result == nullptr || hmacLength != expected.size())
		return std::unexpected(B_ERROR);

	if (CRYPTO_memcmp(expected.data(), header.data() + wire::kHeaderHmacOffset,
			expected.size()) != 0) {
		return std::unexpected(B_PERMISSION_DENIED);
	}

	return {};
}


std::expected<void, status_t>
WrapMasterKey(HeaderBytes& header, std::span<const std::byte, 32> kek,
	std::span<const std::byte> masterKey)
{
	AES_KEY aesKey;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	if (AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(kek.data()),
			256, &aesKey) != 0) {
		return std::unexpected(B_ERROR);
	}

	const int wrappedLength = AES_wrap_key(&aesKey, nullptr,
		reinterpret_cast<unsigned char*>(
			header.data() + wire::kWrappedMasterKeyOffset),
		reinterpret_cast<const unsigned char*>(masterKey.data()),
		static_cast<unsigned int>(masterKey.size()));
#pragma GCC diagnostic pop
	OPENSSL_cleanse(&aesKey, sizeof(aesKey));
	if (wrappedLength != static_cast<int>(masterKey.size() + 8))
		return std::unexpected(B_ERROR);

	return {};
}


std::expected<void, status_t>
UnwrapMasterKey(const ParsedHeader& parsed, std::span<const std::byte, 32> kek,
	secure_buffer<64>& masterKey)
{
	const uint32 masterKeyLength = MasterKeyLength(parsed.cipherId);
	const uint32 wrappedLength = masterKeyLength + 8;

	AES_KEY aesKey;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	if (AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(kek.data()),
			256, &aesKey) != 0) {
		return std::unexpected(B_ERROR);
	}

	const int result = AES_unwrap_key(&aesKey, nullptr,
		reinterpret_cast<unsigned char*>(masterKey.data()),
		reinterpret_cast<const unsigned char*>(parsed.wrappedMasterKey.data()),
		wrappedLength);
#pragma GCC diagnostic pop
	OPENSSL_cleanse(&aesKey, sizeof(aesKey));
	if (result != static_cast<int>(masterKeyLength))
		return std::unexpected(B_PERMISSION_DENIED);

	if (masterKeyLength < masterKey.size()) {
		std::fill(masterKey.data() + masterKeyLength,
			masterKey.data() + masterKey.size(), std::byte{0});
	}

	return {};
}


std::expected<HeaderBytes, status_t>
BuildHeader(std::span<const std::byte> passphrase, uint32 sequenceNumber,
	uint32 cipherId, uint32 sectorSize, uint64 payloadSizeSectors,
	uint32 timeCost, uint32 memoryCostKiB, uint32 parallelism,
	std::span<const std::byte, 16> volumeUuid,
	std::span<const std::byte, 32> salt,
	std::span<const std::byte> masterKey)
{
	if (MasterKeyLength(cipherId) != masterKey.size())
		return std::unexpected(B_BAD_VALUE);

	HeaderBytes header = {};
	for (size_t i = 0; i < wire::kMagic.size(); i++)
		header[i] = std::byte{wire::kMagic[i]};
	WriteLE16(header, wire::kVersionOffset, wire::kHeaderVersion);
	WriteLE16(header, wire::kFlagsOffset, 0);
	WriteLE32(header, wire::kSectorSizeOffset, sectorSize);
	WriteLE64(header, wire::kPayloadOffsetSectorsOffset,
		wire::kPayloadOffsetSectors);
	WriteLE64(header, wire::kPayloadSizeSectorsOffset, payloadSizeSectors);
	WriteLE32(header, wire::kCipherIdOffset, cipherId);
	WriteLE32(header, wire::kKdfIdOffset, kArgon2id);
	WriteLE32(header, wire::kArgon2TimeCostOffset, timeCost);
	WriteLE32(header, wire::kArgon2MemoryCostOffset, memoryCostKiB);
	WriteLE32(header, wire::kArgon2ParallelismOffset, parallelism);
	std::copy(volumeUuid.begin(), volumeUuid.end(),
		header.begin() + wire::kVolumeUuidOffset);
	std::copy(salt.begin(), salt.end(), header.begin() + wire::kKdfSaltOffset);
	WriteLE32(header, wire::kSequenceNumberOffset, sequenceNumber);

	auto derived = DeriveKey(passphrase, salt, timeCost, memoryCostKiB,
		parallelism);
	if (!derived.has_value())
		return std::unexpected(derived.error());

	auto kek = std::span<const std::byte, 32>(derived->data(), 32);
	if (auto result = WrapMasterKey(header, kek, masterKey); !result.has_value())
		return std::unexpected(result.error());

	auto macKey = std::span<const std::byte, 32>(derived->data() + 32, 32);
	if (auto result = ComputeHmac(header, macKey); !result.has_value())
		return std::unexpected(result.error());

	return header;
}

} // namespace


std::expected<ParsedHeader, status_t>
EncryptedVolumeHeader::Parse(std::span<const std::byte> header)
{
	if (header.size() != HeaderBytes{}.size())
		return std::unexpected(B_BAD_VALUE);
	for (size_t i = 0; i < wire::kMagic.size(); i++) {
		if (header[i] != std::byte{wire::kMagic[i]})
			return std::unexpected(B_BAD_DATA);
	}

	ParsedHeader parsed;
	parsed.version = ReadLE16(header, wire::kVersionOffset);
	if (parsed.version > wire::kHeaderVersion)
		return std::unexpected(B_UNSUPPORTED);
	if (parsed.version != wire::kHeaderVersion)
		return std::unexpected(B_BAD_DATA);

	parsed.flags = ReadLE16(header, wire::kFlagsOffset);
	parsed.sectorSize = ReadLE32(header, wire::kSectorSizeOffset);
	parsed.payloadOffsetSectors = ReadLE64(header,
		wire::kPayloadOffsetSectorsOffset);
	parsed.payloadSizeSectors = ReadLE64(header,
		wire::kPayloadSizeSectorsOffset);
	parsed.cipherId = ReadLE32(header, wire::kCipherIdOffset);
	parsed.kdfId = ReadLE32(header, wire::kKdfIdOffset);
	parsed.argon2TimeCost = ReadLE32(header, wire::kArgon2TimeCostOffset);
	parsed.argon2MemoryCostKiB = ReadLE32(header,
		wire::kArgon2MemoryCostOffset);
	parsed.argon2Parallelism = ReadLE32(header, wire::kArgon2ParallelismOffset);
	parsed.sequenceNumber = ReadLE32(header, wire::kSequenceNumberOffset);

	if (parsed.flags != 0
		|| (parsed.sectorSize != 512 && parsed.sectorSize != 4096)
		|| parsed.payloadOffsetSectors != wire::kPayloadOffsetSectors
		|| parsed.payloadSizeSectors == 0
		|| MasterKeyLength(parsed.cipherId) == 0
		|| parsed.kdfId != kArgon2id
		|| !KdfParametersAreBounded(parsed.argon2TimeCost,
			parsed.argon2MemoryCostKiB, parsed.argon2Parallelism)
		|| parsed.sequenceNumber == 0
		|| !AllZero(header.subspan(wire::kReserved0Offset,
			wire::kReserved0Size))
		|| !AllZero(header.subspan(wire::kReserved1Offset,
			wire::kReserved1Size))
		|| !AllZero(header.subspan(wire::kPaddingOffset))) {
		return std::unexpected(B_BAD_DATA);
	}

	std::copy(header.begin() + wire::kVolumeUuidOffset,
		header.begin() + wire::kKdfSaltOffset, parsed.volumeUuid.begin());
	std::copy(header.begin() + wire::kKdfSaltOffset,
		header.begin() + wire::kWrappedMasterKeyOffset,
		parsed.kdfSalt.begin());
	std::copy(header.begin() + wire::kWrappedMasterKeyOffset,
		header.begin() + wire::kSequenceNumberOffset,
		parsed.wrappedMasterKey.begin());

	if (parsed.cipherId == kCipherAES128XTS
		&& !AllZero(std::span<const std::byte>(parsed.wrappedMasterKey)
			.subspan(wire::kAes128WrappedMasterKeySize))) {
		return std::unexpected(B_BAD_DATA);
	}

	return parsed;
}


std::expected<FormattedHeader, status_t>
EncryptedVolumeHeader::Format(std::span<const std::byte> passphrase,
	const FormatOptions& options)
{
	const uint32 masterKeyLength = MasterKeyLength(options.cipherId);
	if (masterKeyLength == 0
		|| (options.sectorSize != 512 && options.sectorSize != 4096)
		|| options.payloadSizeSectors == 0
		|| !KdfParametersAreBounded(options.argon2TimeCost,
			options.argon2MemoryCostKiB, options.argon2Parallelism)) {
		return std::unexpected(B_BAD_VALUE);
	}

	FormattedHeader formatted;
	formatted.masterKeyLength = masterKeyLength;
	if (auto result = FillRandom(std::span<std::byte>(formatted.masterKey.data(),
			masterKeyLength)); !result.has_value()) {
		return std::unexpected(result.error());
	}

	std::array<std::byte, 16> volumeUuid = {};
	std::array<std::byte, 32> salt = {};
	if (auto result = FillRandom(volumeUuid); !result.has_value())
		return std::unexpected(result.error());
	if (auto result = FillRandom(salt); !result.has_value())
		return std::unexpected(result.error());

	const auto header = BuildHeader(passphrase, 1, options.cipherId,
		options.sectorSize, options.payloadSizeSectors, options.argon2TimeCost,
		options.argon2MemoryCostKiB, options.argon2Parallelism, volumeUuid,
		salt, std::span<const std::byte>(formatted.masterKey.data(),
			masterKeyLength));
	if (!header.has_value())
		return std::unexpected(header.error());

	formatted.header = *header;
	return formatted;
}


std::expected<UnlockedHeader, status_t>
EncryptedVolumeHeader::Unlock(std::span<const std::byte> header,
	std::span<const std::byte> passphrase)
{
	const auto parsed = Parse(header);
	if (!parsed.has_value())
		return std::unexpected(parsed.error());

	auto derived = DeriveKey(passphrase,
		std::span<const std::byte, 32>(parsed->kdfSalt), parsed->argon2TimeCost,
		parsed->argon2MemoryCostKiB, parsed->argon2Parallelism);
	if (!derived.has_value())
		return std::unexpected(derived.error());

	HeaderBytes headerBytes = {};
	std::copy(header.begin(), header.end(), headerBytes.begin());

	auto macKey = std::span<const std::byte, 32>(derived->data() + 32, 32);
	if (auto result = VerifyHmac(headerBytes, macKey); !result.has_value()) {
		RecordDerivedAfterCleanse(*derived);
		return std::unexpected(result.error());
	}

	UnlockedHeader unlocked;
	unlocked.cipherId = parsed->cipherId;
	unlocked.masterKeyLength = MasterKeyLength(parsed->cipherId);
	auto kek = std::span<const std::byte, 32>(derived->data(), 32);
	if (auto result = UnwrapMasterKey(*parsed, kek, unlocked.masterKey);
			!result.has_value()) {
		RecordDerivedAfterCleanse(*derived);
		return std::unexpected(result.error());
	}

	RecordDerivedAfterCleanse(*derived);
	return unlocked;
}


std::expected<UnlockedHeader, status_t>
EncryptedVolumeHeader::Open(HeaderPair& pair,
	std::span<const std::byte> passphrase)
{
	auto primary = Unlock(pair.primary, passphrase);
	auto backup = Unlock(pair.backup, passphrase);

	if (primary.has_value() && backup.has_value()) {
		const auto primaryParsed = Parse(pair.primary);
		const auto backupParsed = Parse(pair.backup);
		if (!primaryParsed.has_value() || !backupParsed.has_value())
			return std::unexpected(B_BAD_DATA);
		if (primaryParsed->sequenceNumber == backupParsed->sequenceNumber
			&& pair.primary != pair.backup) {
			return std::unexpected(B_BAD_DATA);
		}
		if (backupParsed->sequenceNumber > primaryParsed->sequenceNumber) {
			pair.primary = pair.backup;
			return std::expected<UnlockedHeader, status_t>(std::move(*backup));
		}
		if (primaryParsed->sequenceNumber > backupParsed->sequenceNumber)
			pair.backup = pair.primary;
		return std::expected<UnlockedHeader, status_t>(std::move(*primary));
	}

	if (primary.has_value()) {
		const auto primaryParsed = Parse(pair.primary);
		const auto backupParsed = Parse(pair.backup);
		if (!primaryParsed.has_value())
			return std::unexpected(B_BAD_DATA);
		if (!backupParsed.has_value()
			|| backupParsed->sequenceNumber <= primaryParsed->sequenceNumber) {
			pair.backup = pair.primary;
		}
		return std::expected<UnlockedHeader, status_t>(std::move(*primary));
	}

	if (backup.has_value()) {
		const auto primaryParsed = Parse(pair.primary);
		const auto backupParsed = Parse(pair.backup);
		if (!backupParsed.has_value())
			return std::unexpected(B_BAD_DATA);
		if (!primaryParsed.has_value()
			|| primaryParsed->sequenceNumber <= backupParsed->sequenceNumber) {
			pair.primary = pair.backup;
		}
		return std::expected<UnlockedHeader, status_t>(std::move(*backup));
	}

	if (primary.error() == B_PERMISSION_DENIED
		&& backup.error() == B_PERMISSION_DENIED) {
		return std::unexpected(B_PERMISSION_DENIED);
	}

	return std::unexpected(B_BAD_DATA);
}


std::expected<void, status_t>
EncryptedVolumeHeader::ChangePassphrase(HeaderPair& pair,
	std::span<const std::byte> oldPassphrase,
	std::span<const std::byte> newPassphrase)
{
	const auto unlocked = Open(pair, oldPassphrase);
	if (!unlocked.has_value())
		return std::unexpected(unlocked.error());

	const auto parsed = Parse(pair.primary);
	if (!parsed.has_value())
		return std::unexpected(parsed.error());
	if (parsed->sequenceNumber == UINT32_MAX)
		return std::unexpected(B_BAD_VALUE);

	std::array<std::byte, 32> salt = {};
	if (auto result = FillRandom(salt); !result.has_value())
		return std::unexpected(result.error());

	const auto header = BuildHeader(newPassphrase,
		parsed->sequenceNumber + 1, parsed->cipherId, parsed->sectorSize,
		parsed->payloadSizeSectors, parsed->argon2TimeCost,
		parsed->argon2MemoryCostKiB, parsed->argon2Parallelism,
		parsed->volumeUuid, salt,
		std::span<const std::byte>(unlocked->masterKey.data(),
			unlocked->masterKeyLength));
	if (!header.has_value())
		return std::unexpected(header.error());

	pair.backup = *header;
	pair.primary = *header;
	return {};
}


std::span<const std::byte>
EncryptedVolumeHeader::DebugLastDerivedBuffer()
{
	return sLastDerivedBuffer;
}

} // namespace BPrivate::EncryptedHome
