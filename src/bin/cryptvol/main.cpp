/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <termios.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <expected>
#include <span>
#include <string_view>
#include <unistd.h>

#include <SupportDefs.h>

#include <encrypted_block_translator.h>
#include <encrypted_volume_header.h>
#include <secure_buffer.h>


namespace {

using namespace BPrivate::EncryptedHome;

constexpr uint32 kDefaultSectorSize = 512;
constexpr size_t kMaxPassphraseLength = 4096;

struct Passphrase {
	secure_buffer<kMaxPassphraseLength> bytes;
	size_t length = 0;
};


void
PrintUsage()
{
	std::fprintf(stderr,
		"usage:\n"
		"  cryptvol create --size <bytes|K|M|G> [--cipher aes128-xts|aes256-xts]"
			" <image>\n"
		"  cryptvol info <image>\n"
		"  cryptvol change-passphrase <image>\n"
		"  cryptvol dump-header <image>\n");
}


std::span<const std::byte>
PassphraseSpan(const Passphrase& passphrase)
{
	return {passphrase.bytes.data(), passphrase.length};
}


std::expected<uint64, status_t>
ParseSize(std::string_view text)
{
	if (text.empty())
		return std::unexpected(B_BAD_VALUE);

	uint64 multiplier = 1;
	const char suffix = text.back();
	if (suffix == 'K' || suffix == 'k') {
		multiplier = 1024;
		text.remove_suffix(1);
	} else if (suffix == 'M' || suffix == 'm') {
		multiplier = 1024 * 1024;
		text.remove_suffix(1);
	} else if (suffix == 'G' || suffix == 'g') {
		multiplier = 1024 * 1024 * 1024;
		text.remove_suffix(1);
	}

	uint64 value = 0;
	const auto result = std::from_chars(text.data(), text.data() + text.size(),
		value);
	if (result.ec != std::errc() || result.ptr != text.data() + text.size())
		return std::unexpected(B_BAD_VALUE);
	if (value > UINT64_MAX / multiplier)
		return std::unexpected(B_BAD_VALUE);
	return value * multiplier;
}


const char*
CipherName(uint32 cipherId)
{
	switch (cipherId) {
		case kCipherAES128XTS:
			return "AES-128-XTS";
		case kCipherAES256XTS:
			return "AES-256-XTS";
		default:
			return "unknown";
	}
}


std::expected<uint32, status_t>
ParseCipher(std::string_view cipher)
{
	if (cipher == "aes128-xts")
		return kCipherAES128XTS;
	if (cipher == "aes256-xts")
		return kCipherAES256XTS;
	return std::unexpected(B_BAD_VALUE);
}


std::expected<Passphrase, status_t>
ReadPassphrase(std::string_view prompt)
{
	Passphrase passphrase;
	bool tooLong = false;
	const bool interactive = isatty(STDIN_FILENO);
	termios original = {};
	bool restoreTerminal = false;

	if (interactive) {
		std::fprintf(stderr, "%.*s", static_cast<int>(prompt.size()),
			prompt.data());
		if (tcgetattr(STDIN_FILENO, &original) == 0) {
			termios noEcho = original;
			noEcho.c_lflag &= static_cast<tcflag_t>(~ECHO);
			if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &noEcho) == 0)
				restoreTerminal = true;
		}
	}

	size_t index = 0;
	for (;;) {
		const int ch = std::getchar();
		if (ch == EOF || ch == '\n')
			break;
		if (index == passphrase.bytes.size()) {
			tooLong = true;
			continue;
		}
		passphrase.bytes.data()[index++] = static_cast<std::byte>(
			static_cast<unsigned char>(ch));
	}
	passphrase.length = index;

	if (restoreTerminal) {
		(void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
		std::fprintf(stderr, "\n");
	}

	if (tooLong)
		return std::unexpected(B_BAD_VALUE);
	if (passphrase.length == 0)
		return std::unexpected(B_BAD_VALUE);
	return passphrase;
}


std::expected<void, status_t>
ReadAt(FILE* file, uint64 offset, std::span<std::byte> buffer)
{
	if (fseeko(file, static_cast<off_t>(offset), SEEK_SET) != 0)
		return std::unexpected(errno == 0 ? B_IO_ERROR : errno);
	if (std::fread(buffer.data(), 1, buffer.size(), file) != buffer.size())
		return std::unexpected(B_IO_ERROR);
	return {};
}


std::expected<void, status_t>
WriteAt(FILE* file, uint64 offset, std::span<const std::byte> buffer)
{
	if (fseeko(file, static_cast<off_t>(offset), SEEK_SET) != 0)
		return std::unexpected(errno == 0 ? B_IO_ERROR : errno);
	if (std::fwrite(buffer.data(), 1, buffer.size(), file) != buffer.size())
		return std::unexpected(B_IO_ERROR);
	return {};
}


std::expected<EncryptedVolumeHeader::HeaderPair, status_t>
ReadHeaderPair(FILE* file)
{
	EncryptedVolumeHeader::HeaderPair pair;
	if (auto result = ReadAt(file, 0, pair.primary); !result.has_value())
		return std::unexpected(result.error());

	const auto primary = EncryptedVolumeHeader::Parse(pair.primary);
	if (primary.has_value()) {
		const uint64 backupOffset = static_cast<uint64>(primary->sectorSize) * 8;
		if (auto result = ReadAt(file, backupOffset, pair.backup);
				!result.has_value()) {
			return std::unexpected(result.error());
		}
		return pair;
	}

	for (const uint32 sectorSize : {uint32{512}, uint32{4096}}) {
		HeaderBytes candidate = {};
		if (auto result = ReadAt(file, static_cast<uint64>(sectorSize) * 8,
				candidate); !result.has_value()) {
			continue;
		}
		const auto parsed = EncryptedVolumeHeader::Parse(candidate);
		if (parsed.has_value() && parsed->sectorSize == sectorSize) {
			pair.backup = candidate;
			return pair;
		}
	}

	return std::unexpected(primary.error());
}


std::expected<uint32, status_t>
HeaderPairSectorSize(const EncryptedVolumeHeader::HeaderPair& pair)
{
	const auto primary = EncryptedVolumeHeader::Parse(pair.primary);
	if (primary.has_value())
		return primary->sectorSize;
	const auto backup = EncryptedVolumeHeader::Parse(pair.backup);
	if (backup.has_value())
		return backup->sectorSize;
	return std::unexpected(B_BAD_DATA);
}


void
PrintParsedHeader(const ParsedHeader& parsed)
{
	std::printf("version: %u\n", parsed.version);
	std::printf("flags: %u\n", parsed.flags);
	std::printf("sector_size: %" B_PRIu32 "\n", parsed.sectorSize);
	std::printf("payload_offset_sectors: %" B_PRIu64 "\n",
		parsed.payloadOffsetSectors);
	std::printf("payload_size_sectors: %" B_PRIu64 "\n",
		parsed.payloadSizeSectors);
	std::printf("cipher: %" B_PRIu32 " (%s)\n", parsed.cipherId,
		CipherName(parsed.cipherId));
	std::printf("kdf: %" B_PRIu32 " (Argon2id)\n", parsed.kdfId);
	std::printf("argon2_time_cost: %" B_PRIu32 "\n", parsed.argon2TimeCost);
	std::printf("argon2_memory_cost_kib: %" B_PRIu32 "\n",
		parsed.argon2MemoryCostKiB);
	std::printf("argon2_parallelism: %" B_PRIu32 "\n",
		parsed.argon2Parallelism);
	std::printf("sequence_number: %" B_PRIu32 "\n", parsed.sequenceNumber);
}


void
PrintDumpHeader(const ParsedHeader& parsed)
{
	std::printf("magic: HAIKUENC\n");
	PrintParsedHeader(parsed);
}


int
CommandCreate(int argc, char** argv)
{
	uint64 payloadBytes = 0;
	uint32 cipherId = kCipherAES256XTS;
	const char* path = nullptr;

	for (int i = 2; i < argc; i++) {
		const std::string_view argument = argv[i];
		if (argument == "--size" && i + 1 < argc) {
			const auto size = ParseSize(argv[++i]);
			if (!size.has_value())
				return 1;
			payloadBytes = *size;
		} else if (argument == "--cipher" && i + 1 < argc) {
			const auto cipher = ParseCipher(argv[++i]);
			if (!cipher.has_value())
				return 1;
			cipherId = *cipher;
		} else if (path == nullptr) {
			path = argv[i];
		} else {
			return 1;
		}
	}

	if (path == nullptr || payloadBytes == 0
		|| payloadBytes % kDefaultSectorSize != 0) {
		return 1;
	}

	const uint64 payloadSectors = payloadBytes / kDefaultSectorSize;
	if (payloadSectors > UINT64_MAX / kDefaultSectorSize - 16)
		return 1;
	const uint64 totalBytes = (payloadSectors + 16) * kDefaultSectorSize;
	if (totalBytes > static_cast<uint64>(OFF_MAX))
		return 1;

	FILE* file = std::fopen(path, "w+b");
	if (file == nullptr)
		return 1;

	if (ftruncate(fileno(file), static_cast<off_t>(totalBytes)) != 0) {
		std::fclose(file);
		return 1;
	}

	auto passphrase = ReadPassphrase("Passphrase: ");
	if (!passphrase.has_value()) {
		std::fclose(file);
		return 1;
	}

	FormatOptions options;
	options.sectorSize = kDefaultSectorSize;
	options.payloadSizeSectors = payloadSectors;
	options.cipherId = cipherId;

	FileBackingStore store(file);
	auto translator = EncryptedBlockTranslator::Format(store,
		PassphraseSpan(*passphrase), options);
	if (!translator.has_value()) {
		std::fclose(file);
		return 1;
	}
	if (auto result = translator->Close(); !result.has_value()) {
		std::fclose(file);
		return 1;
	}

	std::fclose(file);
	return 0;
}


int
CommandInfo(int argc, char** argv)
{
	if (argc != 3)
		return 1;
	FILE* file = std::fopen(argv[2], "rb");
	if (file == nullptr)
		return 1;

	HeaderBytes header = {};
	const auto read = ReadAt(file, 0, header);
	std::fclose(file);
	if (!read.has_value())
		return 1;

	const auto parsed = EncryptedVolumeHeader::Parse(header);
	if (!parsed.has_value())
		return 1;
	PrintParsedHeader(*parsed);
	return 0;
}


int
CommandChangePassphrase(int argc, char** argv)
{
	if (argc != 3)
		return 1;

	FILE* file = std::fopen(argv[2], "r+b");
	if (file == nullptr)
		return 1;

	auto pair = ReadHeaderPair(file);
	if (!pair.has_value()) {
		std::fclose(file);
		return 1;
	}
	const auto sectorSize = HeaderPairSectorSize(*pair);
	if (!sectorSize.has_value()) {
		std::fclose(file);
		return 1;
	}

	auto oldPassphrase = ReadPassphrase("Old passphrase: ");
	if (!oldPassphrase.has_value()) {
		std::fclose(file);
		return 1;
	}
	auto newPassphrase = ReadPassphrase("New passphrase: ");
	if (!newPassphrase.has_value()) {
		std::fclose(file);
		return 1;
	}

	if (auto result = EncryptedVolumeHeader::ChangePassphrase(*pair,
			PassphraseSpan(*oldPassphrase), PassphraseSpan(*newPassphrase));
			!result.has_value()) {
		std::fclose(file);
		return 1;
	}

	const uint64 backupOffset = static_cast<uint64>(*sectorSize) * 8;
	if (auto result = WriteAt(file, backupOffset, pair->backup);
			!result.has_value()) {
		std::fclose(file);
		return 1;
	}
	if (std::fflush(file) != 0 || fsync(fileno(file)) != 0) {
		std::fclose(file);
		return 1;
	}
	if (auto result = WriteAt(file, 0, pair->primary); !result.has_value()) {
		std::fclose(file);
		return 1;
	}
	if (std::fflush(file) != 0 || fsync(fileno(file)) != 0) {
		std::fclose(file);
		return 1;
	}

	std::fclose(file);
	return 0;
}


int
CommandDumpHeader(int argc, char** argv)
{
	if (argc != 3)
		return 1;
	FILE* file = std::fopen(argv[2], "rb");
	if (file == nullptr)
		return 1;

	HeaderBytes header = {};
	const auto read = ReadAt(file, 0, header);
	std::fclose(file);
	if (!read.has_value())
		return 1;

	const auto parsed = EncryptedVolumeHeader::Parse(header);
	if (!parsed.has_value())
		return 1;
	PrintDumpHeader(*parsed);
	return 0;
}

} // namespace


int
main(int argc, char** argv)
{
	if (argc < 2) {
		PrintUsage();
		return 1;
	}

	const std::string_view command = argv[1];
	if (command == "create")
		return CommandCreate(argc, argv);
	if (command == "info")
		return CommandInfo(argc, argv);
	if (command == "change-passphrase")
		return CommandChangePassphrase(argc, argv);
	if (command == "dump-header")
		return CommandDumpHeader(argc, argv);

	PrintUsage();
	return 1;
}
