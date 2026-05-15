/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedBlockTranslatorTest.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

#include <unistd.h>

#include <Errors.h>
#include <SupportDefs.h>

#include <argon2.h>
#include <encrypted_block_translator.h>
#include <encrypted_volume_header.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#include <cppunit/TestCaller.h>
#include <cppunit/TestSuite.h>
#pragma GCC diagnostic pop


namespace {

using namespace BPrivate::EncryptedHome;

constexpr std::string_view kPassphrase = "correct horse battery staple";
constexpr std::string_view kNewPassphrase = "replacement passphrase";
constexpr std::string_view kWrongPassphrase = "wrong passphrase";


std::span<const std::byte>
Bytes(std::string_view string)
{
	return {reinterpret_cast<const std::byte*>(string.data()), string.size()};
}


FormatOptions
TestOptions(uint32 sectorSize = 512, uint64 payloadSizeSectors = 32)
{
	FormatOptions options;
	options.sectorSize = sectorSize;
	options.payloadSizeSectors = payloadSizeSectors;
	options.cipherId = kCipherAES256XTS;
	options.argon2TimeCost = 2;
	options.argon2MemoryCostKiB = 32;
	options.argon2Parallelism = 1;
	return options;
}


class FakeBackingStore final : public BackingStore {
public:
	explicit FakeBackingStore(size_t size)
		:
		fBytes(size)
	{
	}

	[[nodiscard]] std::expected<void, status_t> ReadAt(uint64 offset,
		std::span<std::byte> buffer) override
	{
		if (offset > fBytes.size() || buffer.size() > fBytes.size() - offset)
			return std::unexpected(B_BAD_VALUE);

		std::copy(fBytes.begin() + static_cast<ptrdiff_t>(offset),
			fBytes.begin() + static_cast<ptrdiff_t>(offset + buffer.size()),
			buffer.begin());
		return {};
	}

	[[nodiscard]] std::expected<void, status_t> WriteAt(uint64 offset,
		std::span<const std::byte> buffer) override
	{
		if (offset > fBytes.size() || buffer.size() > fBytes.size() - offset)
			return std::unexpected(B_BAD_VALUE);
		if (fFailNextWrite && offset == fFailWriteOffset) {
			fFailNextWrite = false;
			return std::unexpected(B_IO_ERROR);
		}

		std::copy(buffer.begin(), buffer.end(),
			fBytes.begin() + static_cast<ptrdiff_t>(offset));
		return {};
	}

	[[nodiscard]] std::span<const std::byte> Bytes() const
	{
		return fBytes;
	}

	void FailNextWriteAt(uint64 offset)
	{
		fFailNextWrite = true;
		fFailWriteOffset = offset;
	}

private:
	std::vector<std::byte> fBytes;
	bool fFailNextWrite = false;
	uint64 fFailWriteOffset = 0;
};


size_t
StoreSize(const FormatOptions& options)
{
	return static_cast<size_t>((16 + options.payloadSizeSectors)
		* options.sectorSize);
}


std::vector<std::byte>
Pattern(size_t size, uint8 start)
{
	std::vector<std::byte> bytes(size);
	for (size_t i = 0; i < bytes.size(); i++)
		bytes[i] = std::byte((start + i * 17) & 0xff);
	return bytes;
}


void
AssertError(auto&& result, status_t error)
{
	CPPUNIT_ASSERT(!result.has_value());
	CPPUNIT_ASSERT(result.error() == error);
}


void
WriteLE32(HeaderBytes& bytes, size_t offset, uint32 value)
{
	for (size_t i = 0; i < 4; i++) {
		bytes[offset + i] = std::byte(value & 0xff);
		value >>= 8;
	}
}


void
WriteLE64(HeaderBytes& bytes, size_t offset, uint64 value)
{
	for (size_t i = 0; i < 8; i++) {
		bytes[offset + i] = std::byte(value & 0xff);
		value >>= 8;
	}
}


void
RecomputeHeaderMac(HeaderBytes& header, std::span<const std::byte> passphrase)
{
	const auto parsed = EncryptedVolumeHeader::Parse(header);
	CPPUNIT_ASSERT(parsed.has_value());

	std::array<std::byte, 64> derived = {};
	const int result = argon2id_hash_raw(parsed->argon2TimeCost,
		parsed->argon2MemoryCostKiB, parsed->argon2Parallelism,
		passphrase.data(), passphrase.size(), parsed->kdfSalt.data(),
		parsed->kdfSalt.size(), derived.data(), derived.size());
	CPPUNIT_ASSERT(result == ARGON2_OK);

	unsigned int hmacLength = 0;
	unsigned char* hmac = HMAC(EVP_sha256(), derived.data() + 32, 32,
		reinterpret_cast<const unsigned char*>(header.data()), 0x0c0,
		reinterpret_cast<unsigned char*>(header.data() + 0x0c0), &hmacLength);
	CPPUNIT_ASSERT(hmac != nullptr);
	CPPUNIT_ASSERT(hmacLength == 32);
	OPENSSL_cleanse(derived.data(), derived.size());
}

} // namespace


CppUnit::Test*
EncryptedBlockTranslatorTest::Suite()
{
	CppUnit::TestSuite* suite = new CppUnit::TestSuite(
		"EncryptedBlockTranslatorTest");
	typedef CppUnit::TestCaller<EncryptedBlockTranslatorTest> TestCaller;

	suite->addTest(new TestCaller("format then reopen",
		&EncryptedBlockTranslatorTest::TestFormatThenReopen));
	suite->addTest(new TestCaller("format zero fills payload",
		&EncryptedBlockTranslatorTest::TestFormatZeroFillsPayload));
	suite->addTest(new TestCaller(
		"format does not extend small file for alternate backup clear",
		&EncryptedBlockTranslatorTest
			::TestFormatDoesNotExtendSmallFileForAlternateBackupClear));
	suite->addTest(new TestCaller(
		"format does not clear outside declared volume",
		&EncryptedBlockTranslatorTest
			::TestFormatDoesNotClearOutsideDeclaredVolume));
	suite->addTest(new TestCaller("random IO",
		&EncryptedBlockTranslatorTest::TestRandomIO));
	suite->addTest(new TestCaller("unaligned read fails",
		&EncryptedBlockTranslatorTest::TestUnalignedReadFails));
	suite->addTest(new TestCaller("reject backing offset wraparound",
		&EncryptedBlockTranslatorTest::TestRejectBackingOffsetWraparound));
	suite->addTest(new TestCaller("persist across close",
		&EncryptedBlockTranslatorTest::TestPersistAcrossClose));
	suite->addTest(new TestCaller("close flushes writes",
		&EncryptedBlockTranslatorTest::TestCloseFlushesWrites));
	suite->addTest(new TestCaller("file backing store large offset",
		&EncryptedBlockTranslatorTest::TestFileBackingStoreLargeOffset));
	suite->addTest(new TestCaller("wrong passphrase",
		&EncryptedBlockTranslatorTest::TestWrongPassphrase));
	suite->addTest(new TestCaller("header corruption detected",
		&EncryptedBlockTranslatorTest::TestHeaderCorruptionDetected));
	suite->addTest(new TestCaller("backup header recovery",
		&EncryptedBlockTranslatorTest::TestBackupHeaderRecovery));
	suite->addTest(new TestCaller("failed repair preserves backup header",
		&EncryptedBlockTranslatorTest::TestFailedRepairPreservesBackupHeader));
	suite->addTest(new TestCaller(
		"recovery ignores unauthenticated primary metadata",
		&EncryptedBlockTranslatorTest
			::TestRecoveryIgnoresUnauthenticatedPrimaryMetadata));
	suite->addTest(new TestCaller(
		"backup header recovery ignores unauthenticated sector size",
		&EncryptedBlockTranslatorTest
			::TestBackupHeaderRecoveryIgnoresUnauthenticatedSectorSize));
	suite->addTest(new TestCaller("open does not rollback newer backup",
		&EncryptedBlockTranslatorTest::TestOpenDoesNotRollbackNewerBackup));
	suite->addTest(new TestCaller("open does not rollback newer 4 KiB backup",
		&EncryptedBlockTranslatorTest
			::TestOpenDoesNotRollbackNewerFourKiBBackup));
	suite->addTest(new TestCaller(
		"authenticated primary ignores stale backup at wrong offset",
		&EncryptedBlockTranslatorTest
			::TestAuthenticatedPrimaryIgnoresStaleBackupAtWrongOffset));
	suite->addTest(new TestCaller(
		"old passphrase cannot open stale backup after reformat",
		&EncryptedBlockTranslatorTest
			::TestOldPassphraseCannotOpenStaleBackupAfterReformat));
	suite->addTest(new TestCaller(
		"corrupt primary rejects ambiguous stale backup",
		&EncryptedBlockTranslatorTest
			::TestCorruptPrimaryRejectsAmbiguousStaleBackup));
	suite->addTest(new TestCaller(
		"corrupt primary rejects ambiguous stale 4 KiB backup",
		&EncryptedBlockTranslatorTest
			::TestCorruptPrimaryRejectsAmbiguousStaleFourKiBBackup));
	suite->addTest(new TestCaller("4 KiB sectors",
		&EncryptedBlockTranslatorTest::TestFourKiBSectors));

	return suite;
}


void
EncryptedBlockTranslatorTest::TestFormatThenReopen()
{
	const FormatOptions options = TestOptions();
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());

	const std::vector<std::byte> plaintext = Pattern(1024, 3);
	CPPUNIT_ASSERT(translator->WriteAt(0, plaintext).has_value());

	const size_t payloadOffset = 16 * options.sectorSize;
	CPPUNIT_ASSERT(!std::equal(plaintext.begin(), plaintext.end(),
		store.Bytes().begin() + static_cast<ptrdiff_t>(payloadOffset)));

	CPPUNIT_ASSERT(translator->Close().has_value());

	auto reopened = EncryptedBlockTranslator::Open(store, Bytes(kPassphrase));
	CPPUNIT_ASSERT(reopened.has_value());

	std::vector<std::byte> readBack(plaintext.size());
	CPPUNIT_ASSERT(reopened->ReadAt(0, readBack).has_value());
	CPPUNIT_ASSERT(readBack == plaintext);
}


void
EncryptedBlockTranslatorTest::TestFormatZeroFillsPayload()
{
	const FormatOptions options = TestOptions();
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());

	std::vector<std::byte> readBack(options.sectorSize
		* options.payloadSizeSectors);
	CPPUNIT_ASSERT(translator->ReadAt(0, readBack).has_value());
	CPPUNIT_ASSERT(std::all_of(readBack.begin(), readBack.end(),
		[](std::byte byte) { return byte == std::byte{0}; }));

	const size_t payloadOffset = 16 * options.sectorSize;
	CPPUNIT_ASSERT(!std::all_of(store.Bytes().begin()
			+ static_cast<ptrdiff_t>(payloadOffset), store.Bytes().end(),
		[](std::byte byte) { return byte == std::byte{0}; }));
}


void
EncryptedBlockTranslatorTest::TestFormatDoesNotExtendSmallFileForAlternateBackupClear()
{
	const FormatOptions options = TestOptions(512, 32);
	std::FILE* file = std::tmpfile();
	CPPUNIT_ASSERT(file != nullptr);

	std::vector<std::byte> backing(StoreSize(options));
	CPPUNIT_ASSERT(std::fwrite(backing.data(), 1, backing.size(), file)
		== backing.size());
	CPPUNIT_ASSERT(std::fflush(file) == 0);

	FileBackingStore store(file);
	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	const int fd = fileno(file);
	CPPUNIT_ASSERT(fd >= 0);
	const off_t size = lseek(fd, 0, SEEK_END);
	CPPUNIT_ASSERT(size == static_cast<off_t>(StoreSize(options)));
	std::fclose(file);
}


void
EncryptedBlockTranslatorTest::TestFormatDoesNotClearOutsideDeclaredVolume()
{
	const FormatOptions options = TestOptions(512, 32);
	const size_t largerBackingSize = 8 * 4096 + HeaderBytes{}.size();
	FakeBackingStore store(largerBackingSize);

	std::vector<std::byte> marker(HeaderBytes{}.size(), std::byte{0x7d});
	CPPUNIT_ASSERT(store.WriteAt(8 * 4096, marker).has_value());

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	std::vector<std::byte> after(marker.size());
	CPPUNIT_ASSERT(store.ReadAt(8 * 4096, after).has_value());
	CPPUNIT_ASSERT(after == marker);
}


void
EncryptedBlockTranslatorTest::TestRandomIO()
{
	const FormatOptions options = TestOptions(512, 64);
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());

	std::vector<std::byte> expected(options.sectorSize
		* options.payloadSizeSectors);
	const auto first = Pattern(512, 11);
	const auto middle = Pattern(1536, 67);
	const auto last = Pattern(512, 129);

	CPPUNIT_ASSERT(translator->WriteAt(0, first).has_value());
	std::copy(first.begin(), first.end(), expected.begin());

	CPPUNIT_ASSERT(translator->WriteAt(17 * options.sectorSize,
		middle).has_value());
	std::copy(middle.begin(), middle.end(), expected.begin()
		+ static_cast<ptrdiff_t>(17 * options.sectorSize));

	CPPUNIT_ASSERT(translator->WriteAt(63 * options.sectorSize,
		last).has_value());
	std::copy(last.begin(), last.end(), expected.begin()
		+ static_cast<ptrdiff_t>(63 * options.sectorSize));

	std::vector<std::byte> readBack(expected.size());
	CPPUNIT_ASSERT(translator->ReadAt(0, readBack).has_value());
	CPPUNIT_ASSERT(readBack == expected);
}


void
EncryptedBlockTranslatorTest::TestUnalignedReadFails()
{
	const FormatOptions options = TestOptions();
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());

	std::array<std::byte, 511> buffer = {};
	AssertError(translator->ReadAt(0, buffer), B_BAD_VALUE);

	std::array<std::byte, 512> sector = {};
	AssertError(translator->ReadAt(1, sector), B_BAD_VALUE);
	AssertError(translator->WriteAt(1, sector), B_BAD_VALUE);
}


void
EncryptedBlockTranslatorTest::TestRejectBackingOffsetWraparound()
{
	const FormatOptions options = TestOptions();
	auto formatted = EncryptedVolumeHeader::Format(Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(formatted.has_value());

	HeaderBytes header = formatted->header;
	WriteLE64(header, 0x018, UINT64_MAX / options.sectorSize);
	RecomputeHeaderMac(header, Bytes(kPassphrase));

	FakeBackingStore store(16 * options.sectorSize);
	CPPUNIT_ASSERT(store.WriteAt(0, header).has_value());
	CPPUNIT_ASSERT(store.WriteAt(8 * options.sectorSize, header).has_value());

	AssertError(EncryptedBlockTranslator::Open(store, Bytes(kPassphrase)),
		B_BAD_VALUE);
}


void
EncryptedBlockTranslatorTest::TestPersistAcrossClose()
{
	const FormatOptions options = TestOptions();
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());

	const auto plaintext = Pattern(512, 213);
	CPPUNIT_ASSERT(translator->WriteAt(4 * options.sectorSize,
		plaintext).has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	auto reopened = EncryptedBlockTranslator::Open(store, Bytes(kPassphrase));
	CPPUNIT_ASSERT(reopened.has_value());

	std::vector<std::byte> readBack(plaintext.size());
	CPPUNIT_ASSERT(reopened->ReadAt(4 * options.sectorSize,
		readBack).has_value());
	CPPUNIT_ASSERT(readBack == plaintext);
}


void
EncryptedBlockTranslatorTest::TestCloseFlushesWrites()
{
	const FormatOptions options = TestOptions();
	std::FILE* file = std::tmpfile();
	CPPUNIT_ASSERT(file != nullptr);

	std::vector<std::byte> backing(StoreSize(options));
	CPPUNIT_ASSERT(std::fwrite(backing.data(), 1, backing.size(), file)
		== backing.size());
	CPPUNIT_ASSERT(std::fflush(file) == 0);

	FileBackingStore store(file);
	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());

	const auto plaintext = Pattern(512, 31);
	CPPUNIT_ASSERT(translator->WriteAt(0, plaintext).has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	std::FILE* duplicate = std::tmpfile();
	CPPUNIT_ASSERT(duplicate != nullptr);
	CPPUNIT_ASSERT(std::fseek(file, 0, SEEK_SET) == 0);
	std::vector<std::byte> persisted(StoreSize(options));
	CPPUNIT_ASSERT(std::fread(persisted.data(), 1, persisted.size(), file)
		== persisted.size());
	CPPUNIT_ASSERT(std::fwrite(persisted.data(), 1, persisted.size(),
		duplicate) == persisted.size());
	CPPUNIT_ASSERT(std::fflush(duplicate) == 0);

	FileBackingStore reopenedStore(duplicate);
	auto reopened = EncryptedBlockTranslator::Open(reopenedStore,
		Bytes(kPassphrase));
	CPPUNIT_ASSERT(reopened.has_value());

	std::vector<std::byte> readBack(plaintext.size());
	CPPUNIT_ASSERT(reopened->ReadAt(0, readBack).has_value());
	CPPUNIT_ASSERT(readBack == plaintext);
	CPPUNIT_ASSERT(reopened->Close().has_value());

	std::fclose(duplicate);
	std::fclose(file);
}


void
EncryptedBlockTranslatorTest::TestFileBackingStoreLargeOffset()
{
	constexpr uint64 kLargeOffset = 0x80000000ULL;
	std::FILE* file = std::tmpfile();
	CPPUNIT_ASSERT(file != nullptr);

	FileBackingStore store(file);
	std::array<std::byte, 1> value = {std::byte{0x5a}};
	CPPUNIT_ASSERT(store.WriteAt(kLargeOffset, value).has_value());
	CPPUNIT_ASSERT(store.Flush().has_value());

	std::array<std::byte, 1> readBack = {};
	CPPUNIT_ASSERT(store.ReadAt(kLargeOffset, readBack).has_value());
	CPPUNIT_ASSERT(readBack == value);

	std::fclose(file);
}


void
EncryptedBlockTranslatorTest::TestWrongPassphrase()
{
	const FormatOptions options = TestOptions();
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	AssertError(EncryptedBlockTranslator::Open(store, Bytes(kWrongPassphrase)),
		B_PERMISSION_DENIED);
}


void
EncryptedBlockTranslatorTest::TestHeaderCorruptionDetected()
{
	const FormatOptions options = TestOptions();
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	std::array<std::byte, 1> corrupt = {std::byte{'X'}};
	CPPUNIT_ASSERT(store.WriteAt(0, corrupt).has_value());
	CPPUNIT_ASSERT(store.WriteAt(8 * options.sectorSize, corrupt).has_value());

	AssertError(EncryptedBlockTranslator::Open(store, Bytes(kPassphrase)),
		B_BAD_DATA);
}


void
EncryptedBlockTranslatorTest::TestBackupHeaderRecovery()
{
	const FormatOptions options = TestOptions();
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());

	const auto plaintext = Pattern(512, 99);
	CPPUNIT_ASSERT(translator->WriteAt(0, plaintext).has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	std::array<std::byte, 1> corrupt = {std::byte{'X'}};
	CPPUNIT_ASSERT(store.WriteAt(0, corrupt).has_value());

	auto reopened = EncryptedBlockTranslator::Open(store, Bytes(kPassphrase));
	CPPUNIT_ASSERT(reopened.has_value());

	std::vector<std::byte> readBack(plaintext.size());
	CPPUNIT_ASSERT(reopened->ReadAt(0, readBack).has_value());
	CPPUNIT_ASSERT(readBack == plaintext);
}


void
EncryptedBlockTranslatorTest::TestFailedRepairPreservesBackupHeader()
{
	const FormatOptions options = TestOptions();
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	std::array<std::byte, 1> corrupt = {std::byte{'X'}};
	CPPUNIT_ASSERT(store.WriteAt(0, corrupt).has_value());
	store.FailNextWriteAt(8 * options.sectorSize);

	AssertError(EncryptedBlockTranslator::Open(store, Bytes(kPassphrase)),
		B_IO_ERROR);

	auto reopened = EncryptedBlockTranslator::Open(store, Bytes(kPassphrase));
	CPPUNIT_ASSERT(reopened.has_value());
}


void
EncryptedBlockTranslatorTest::TestRecoveryIgnoresUnauthenticatedPrimaryMetadata()
{
	const FormatOptions options = TestOptions();
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());

	const auto plaintext = Pattern(512, 233);
	CPPUNIT_ASSERT(translator->WriteAt(0, plaintext).has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	HeaderBytes primary = {};
	CPPUNIT_ASSERT(store.ReadAt(0, primary).has_value());
	WriteLE32(primary, 0x00c, 4096);
	WriteLE32(primary, 0x0b8, 100);
	CPPUNIT_ASSERT(store.WriteAt(0, primary).has_value());

	auto reopened = EncryptedBlockTranslator::Open(store, Bytes(kPassphrase));
	CPPUNIT_ASSERT(reopened.has_value());

	std::vector<std::byte> readBack(plaintext.size());
	CPPUNIT_ASSERT(reopened->ReadAt(0, readBack).has_value());
	CPPUNIT_ASSERT(readBack == plaintext);
}


void
EncryptedBlockTranslatorTest::TestOpenDoesNotRollbackNewerBackup()
{
	const FormatOptions options = TestOptions();
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	EncryptedVolumeHeader::HeaderPair pair;
	CPPUNIT_ASSERT(store.ReadAt(0, pair.primary).has_value());
	pair.backup = pair.primary;
	CPPUNIT_ASSERT(EncryptedVolumeHeader::ChangePassphrase(pair,
		Bytes(kPassphrase), Bytes(kNewPassphrase)).has_value());
	CPPUNIT_ASSERT(store.WriteAt(8 * options.sectorSize,
		pair.backup).has_value());

	auto openedOld = EncryptedBlockTranslator::Open(store, Bytes(kPassphrase));
	CPPUNIT_ASSERT(openedOld.has_value());
	CPPUNIT_ASSERT(openedOld->Close().has_value());

	auto openedNew = EncryptedBlockTranslator::Open(store,
		Bytes(kNewPassphrase));
	CPPUNIT_ASSERT(openedNew.has_value());
}


void
EncryptedBlockTranslatorTest
	::TestBackupHeaderRecoveryIgnoresUnauthenticatedSectorSize()
{
	const FormatOptions options = TestOptions(4096, 4);
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());

	const auto plaintext = Pattern(4096, 147);
	CPPUNIT_ASSERT(translator->WriteAt(0, plaintext).has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	std::array<std::byte, 4> sectorSize512 = {
		std::byte{0x00}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00}
	};
	CPPUNIT_ASSERT(store.WriteAt(0x00c, sectorSize512).has_value());

	auto reopened = EncryptedBlockTranslator::Open(store, Bytes(kPassphrase));
	CPPUNIT_ASSERT(reopened.has_value());

	std::vector<std::byte> readBack(plaintext.size());
	CPPUNIT_ASSERT(reopened->ReadAt(0, readBack).has_value());
	CPPUNIT_ASSERT(readBack == plaintext);
}


void
EncryptedBlockTranslatorTest::TestOpenDoesNotRollbackNewerFourKiBBackup()
{
	const FormatOptions options = TestOptions(4096, 4);
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	EncryptedVolumeHeader::HeaderPair pair;
	CPPUNIT_ASSERT(store.ReadAt(0, pair.primary).has_value());
	pair.backup = pair.primary;
	CPPUNIT_ASSERT(EncryptedVolumeHeader::ChangePassphrase(pair,
		Bytes(kPassphrase), Bytes(kNewPassphrase)).has_value());
	CPPUNIT_ASSERT(store.WriteAt(8 * options.sectorSize,
		pair.backup).has_value());

	auto openedOld = EncryptedBlockTranslator::Open(store, Bytes(kPassphrase));
	CPPUNIT_ASSERT(openedOld.has_value());
	CPPUNIT_ASSERT(openedOld->Close().has_value());

	auto openedNew = EncryptedBlockTranslator::Open(store,
		Bytes(kNewPassphrase));
	CPPUNIT_ASSERT(openedNew.has_value());
}


void
EncryptedBlockTranslatorTest
	::TestAuthenticatedPrimaryIgnoresStaleBackupAtWrongOffset()
{
	const FormatOptions oldOptions = TestOptions(512, 96);
	const FormatOptions newOptions = TestOptions(4096, 4);
	FakeBackingStore store(std::max(StoreSize(oldOptions),
		StoreSize(newOptions)));

	auto oldTranslator = EncryptedBlockTranslator::Format(store,
		Bytes(kPassphrase), oldOptions);
	CPPUNIT_ASSERT(oldTranslator.has_value());
	CPPUNIT_ASSERT(oldTranslator->Close().has_value());

	auto newTranslator = EncryptedBlockTranslator::Format(store,
		Bytes(kPassphrase), newOptions);
	CPPUNIT_ASSERT(newTranslator.has_value());

	const auto plaintext = Pattern(4096, 199);
	CPPUNIT_ASSERT(newTranslator->WriteAt(0, plaintext).has_value());
	CPPUNIT_ASSERT(newTranslator->Close().has_value());

	auto reopened = EncryptedBlockTranslator::Open(store, Bytes(kPassphrase));
	CPPUNIT_ASSERT(reopened.has_value());

	std::vector<std::byte> readBack(plaintext.size());
	CPPUNIT_ASSERT(reopened->ReadAt(0, readBack).has_value());
	CPPUNIT_ASSERT(readBack == plaintext);
}


void
EncryptedBlockTranslatorTest::TestOldPassphraseCannotOpenStaleBackupAfterReformat()
{
	const FormatOptions oldOptions = TestOptions(4096, 4);
	const FormatOptions newOptions = TestOptions(512, 32);
	FakeBackingStore store(std::max(StoreSize(oldOptions),
		StoreSize(newOptions)));

	auto oldTranslator = EncryptedBlockTranslator::Format(store,
		Bytes(kPassphrase), oldOptions);
	CPPUNIT_ASSERT(oldTranslator.has_value());
	CPPUNIT_ASSERT(oldTranslator->Close().has_value());

	auto newTranslator = EncryptedBlockTranslator::Format(store,
		Bytes(kNewPassphrase), newOptions);
	CPPUNIT_ASSERT(newTranslator.has_value());
	CPPUNIT_ASSERT(newTranslator->Close().has_value());

	AssertError(EncryptedBlockTranslator::Open(store, Bytes(kPassphrase)),
		B_PERMISSION_DENIED);

	auto reopened = EncryptedBlockTranslator::Open(store, Bytes(kNewPassphrase));
	CPPUNIT_ASSERT(reopened.has_value());
}


void
EncryptedBlockTranslatorTest
	::TestCorruptPrimaryRejectsAmbiguousStaleBackup()
{
	const FormatOptions oldOptions = TestOptions(512, 96);
	const FormatOptions newOptions = TestOptions(4096, 4);
	FakeBackingStore store(std::max(StoreSize(oldOptions),
		StoreSize(newOptions)));

	auto oldTranslator = EncryptedBlockTranslator::Format(store,
		Bytes(kPassphrase), oldOptions);
	CPPUNIT_ASSERT(oldTranslator.has_value());
	CPPUNIT_ASSERT(oldTranslator->Close().has_value());

	auto newTranslator = EncryptedBlockTranslator::Format(store,
		Bytes(kPassphrase), newOptions);
	CPPUNIT_ASSERT(newTranslator.has_value());

	const auto plaintext = Pattern(4096, 211);
	CPPUNIT_ASSERT(newTranslator->WriteAt(0, plaintext).has_value());
	CPPUNIT_ASSERT(newTranslator->Close().has_value());

	const std::array<std::byte, 1> corrupt = {std::byte{'X'}};
	CPPUNIT_ASSERT(store.WriteAt(0, corrupt).has_value());

	AssertError(EncryptedBlockTranslator::Open(store, Bytes(kPassphrase)),
		B_BAD_DATA);
}


void
EncryptedBlockTranslatorTest
	::TestCorruptPrimaryRejectsAmbiguousStaleFourKiBBackup()
{
	const FormatOptions oldOptions = TestOptions(4096, 4);
	const FormatOptions newOptions = TestOptions(512, 32);
	FakeBackingStore store(std::max(StoreSize(oldOptions),
		StoreSize(newOptions)));

	auto oldTranslator = EncryptedBlockTranslator::Format(store,
		Bytes(kPassphrase), oldOptions);
	CPPUNIT_ASSERT(oldTranslator.has_value());
	CPPUNIT_ASSERT(oldTranslator->Close().has_value());

	auto newTranslator = EncryptedBlockTranslator::Format(store,
		Bytes(kPassphrase), newOptions);
	CPPUNIT_ASSERT(newTranslator.has_value());

	const auto plaintext = Pattern(512, 223);
	CPPUNIT_ASSERT(newTranslator->WriteAt(0, plaintext).has_value());
	CPPUNIT_ASSERT(newTranslator->Close().has_value());

	const std::array<std::byte, 1> corrupt = {std::byte{'X'}};
	CPPUNIT_ASSERT(store.WriteAt(0, corrupt).has_value());

	AssertError(EncryptedBlockTranslator::Open(store, Bytes(kPassphrase)),
		B_BAD_DATA);
}


void
EncryptedBlockTranslatorTest::TestFourKiBSectors()
{
	const FormatOptions options = TestOptions(4096, 4);
	FakeBackingStore store(StoreSize(options));

	auto translator = EncryptedBlockTranslator::Format(store, Bytes(kPassphrase),
		options);
	CPPUNIT_ASSERT(translator.has_value());

	const auto plaintext = Pattern(4096, 41);
	CPPUNIT_ASSERT(translator->WriteAt(0, plaintext).has_value());
	CPPUNIT_ASSERT(translator->Close().has_value());

	auto reopened = EncryptedBlockTranslator::Open(store, Bytes(kPassphrase));
	CPPUNIT_ASSERT(reopened.has_value());

	std::vector<std::byte> readBack(plaintext.size());
	CPPUNIT_ASSERT(reopened->ReadAt(0, readBack).has_value());
	CPPUNIT_ASSERT(readBack == plaintext);
}
