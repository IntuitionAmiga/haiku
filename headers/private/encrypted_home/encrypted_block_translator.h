/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef _PRIVATE_ENCRYPTED_HOME_ENCRYPTED_BLOCK_TRANSLATOR_H
#define _PRIVATE_ENCRYPTED_HOME_ENCRYPTED_BLOCK_TRANSLATOR_H


#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <span>

#include <SupportDefs.h>

#include <encrypted_volume_header.h>
#include <secure_buffer.h>


struct xts_haiku_context;


namespace BPrivate::EncryptedHome {

class BackingStore {
public:
	virtual ~BackingStore() = default;

	[[nodiscard]] virtual std::expected<void, status_t> ReadAt(uint64 offset,
		std::span<std::byte> buffer) = 0;
	[[nodiscard]] virtual std::expected<void, status_t> WriteAt(uint64 offset,
		std::span<const std::byte> buffer) = 0;
	[[nodiscard]] virtual std::expected<void, status_t> Flush();
};

class FileBackingStore final : public BackingStore {
public:
	explicit FileBackingStore(std::FILE* file);

	[[nodiscard]] std::expected<void, status_t> ReadAt(uint64 offset,
		std::span<std::byte> buffer) override;
	[[nodiscard]] std::expected<void, status_t> WriteAt(uint64 offset,
		std::span<const std::byte> buffer) override;
	[[nodiscard]] std::expected<void, status_t> Flush() override;

private:
	std::FILE* fFile = nullptr;
};

class EncryptedBlockTranslator {
public:
	EncryptedBlockTranslator();
	EncryptedBlockTranslator(EncryptedBlockTranslator&& other) noexcept;
	EncryptedBlockTranslator& operator=(
		EncryptedBlockTranslator&& other) noexcept;
	EncryptedBlockTranslator(const EncryptedBlockTranslator&) = delete;
	EncryptedBlockTranslator& operator=(
		const EncryptedBlockTranslator&) = delete;
	~EncryptedBlockTranslator();

	[[nodiscard]] static std::expected<EncryptedBlockTranslator, status_t>
		Format(BackingStore& store, std::span<const std::byte> passphrase,
			const FormatOptions& options);
	[[nodiscard]] static std::expected<EncryptedBlockTranslator, status_t>
		Open(BackingStore& store, std::span<const std::byte> passphrase);

	[[nodiscard]] std::expected<void, status_t> ReadAt(uint64 offset,
		std::span<std::byte> buffer);
	[[nodiscard]] std::expected<void, status_t> WriteAt(uint64 offset,
		std::span<const std::byte> buffer);
	[[nodiscard]] std::expected<void, status_t> Close();

private:
	[[nodiscard]] static std::expected<EncryptedBlockTranslator, status_t>
		FromUnlocked(BackingStore& store, UnlockedHeader&& unlocked,
			const ParsedHeader& parsed);
	[[nodiscard]] uint64 PayloadSize() const;

	BackingStore* fStore = nullptr;
	uint32 fSectorSize = 0;
	uint64 fPayloadSizeSectors = 0;
	uint64 fPayloadSizeBytes = 0;
	uint32 fCipherId = 0;
	secure_buffer<64> fMasterKey;
	uint32 fMasterKeyLength = 0;
	xts_haiku_context* fXts = nullptr;
	bool fOpen = false;
};

} // namespace BPrivate::EncryptedHome


#endif	// _PRIVATE_ENCRYPTED_HOME_ENCRYPTED_BLOCK_TRANSLATOR_H
