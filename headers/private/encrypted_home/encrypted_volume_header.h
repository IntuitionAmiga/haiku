/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef _PRIVATE_ENCRYPTED_HOME_ENCRYPTED_VOLUME_HEADER_H
#define _PRIVATE_ENCRYPTED_HOME_ENCRYPTED_VOLUME_HEADER_H


#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

#include <SupportDefs.h>

#include <secure_buffer.h>


namespace BPrivate::EncryptedHome {

using HeaderBytes = std::array<std::byte, 4096>;

constexpr uint32 kCipherAES128XTS = 1;
constexpr uint32 kCipherAES256XTS = 2;
constexpr uint32 kArgon2id = 1;

struct FormatOptions {
	uint32 sectorSize = 512;
	uint64 payloadSizeSectors = 0;
	uint32 cipherId = kCipherAES256XTS;
	uint32 argon2TimeCost = 3;
	uint32 argon2MemoryCostKiB = 65536;
	uint32 argon2Parallelism = 4;
};

struct ParsedHeader {
	uint16 version = 0;
	uint16 flags = 0;
	uint32 sectorSize = 0;
	uint64 payloadOffsetSectors = 0;
	uint64 payloadSizeSectors = 0;
	uint32 cipherId = 0;
	uint32 kdfId = 0;
	uint32 argon2TimeCost = 0;
	uint32 argon2MemoryCostKiB = 0;
	uint32 argon2Parallelism = 0;
	std::array<std::byte, 16> volumeUuid = {};
	std::array<std::byte, 32> kdfSalt = {};
	std::array<std::byte, 72> wrappedMasterKey = {};
	uint32 sequenceNumber = 0;
};

struct FormattedHeader {
	FormattedHeader() = default;
	FormattedHeader(FormattedHeader&&) noexcept = default;
	FormattedHeader& operator=(FormattedHeader&&) noexcept = default;
	FormattedHeader(const FormattedHeader&) = delete;
	FormattedHeader& operator=(const FormattedHeader&) = delete;

	HeaderBytes header = {};
	secure_buffer<64> masterKey;
	uint32 masterKeyLength = 0;
};

struct UnlockedHeader {
	UnlockedHeader() = default;
	UnlockedHeader(UnlockedHeader&&) noexcept = default;
	UnlockedHeader& operator=(UnlockedHeader&&) noexcept = default;
	UnlockedHeader(const UnlockedHeader&) = delete;
	UnlockedHeader& operator=(const UnlockedHeader&) = delete;

	uint32 cipherId = 0;
	secure_buffer<64> masterKey;
	uint32 masterKeyLength = 0;
};

class EncryptedVolumeHeader {
public:
	struct HeaderPair {
		HeaderBytes primary = {};
		HeaderBytes backup = {};
	};

	[[nodiscard]] static std::expected<ParsedHeader, status_t> Parse(
		std::span<const std::byte> header);
	[[nodiscard]] static std::expected<FormattedHeader, status_t> Format(
		std::span<const std::byte> passphrase,
		const FormatOptions& options);
	[[nodiscard]] static std::expected<UnlockedHeader, status_t> Unlock(
		std::span<const std::byte> header,
		std::span<const std::byte> passphrase);
	[[nodiscard]] static std::expected<UnlockedHeader, status_t> Open(
		HeaderPair& pair, std::span<const std::byte> passphrase);
	[[nodiscard]] static std::expected<void, status_t> ChangePassphrase(
		HeaderPair& pair, std::span<const std::byte> oldPassphrase,
		std::span<const std::byte> newPassphrase);

	[[nodiscard]] static std::span<const std::byte> DebugLastDerivedBuffer();
};

} // namespace BPrivate::EncryptedHome


#endif	// _PRIVATE_ENCRYPTED_HOME_ENCRYPTED_VOLUME_HEADER_H
