/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedVolumeHeaderTest.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

#include <SupportDefs.h>

#include <argon2.h>
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
TestOptions(uint32 cipherId = kCipherAES256XTS)
{
	FormatOptions options;
	options.sectorSize = 512;
	options.payloadSizeSectors = 4096;
	options.cipherId = cipherId;
	options.argon2TimeCost = 2;
	options.argon2MemoryCostKiB = 32;
	options.argon2Parallelism = 1;
	return options;
}


EncryptedVolumeHeader::HeaderPair
FormattedPair(const FormatOptions& options = TestOptions())
{
	auto formatted = EncryptedVolumeHeader::Format(Bytes(kPassphrase), options);
	CPPUNIT_ASSERT(formatted.has_value());
	return {formatted->header, formatted->header};
}


void
AssertPermissionDenied(auto&& result)
{
	CPPUNIT_ASSERT(!result.has_value());
	CPPUNIT_ASSERT(result.error() == B_PERMISSION_DENIED);
}


uint32
SequenceNumber(const HeaderBytes& header)
{
	const auto parsed = EncryptedVolumeHeader::Parse(header);
	CPPUNIT_ASSERT(parsed.has_value());
	return parsed->sequenceNumber;
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
EncryptedVolumeHeaderTest::Suite()
{
	CppUnit::TestSuite* suite = new CppUnit::TestSuite(
		"EncryptedVolumeHeaderTest");
	typedef CppUnit::TestCaller<EncryptedVolumeHeaderTest> TestCaller;

	suite->addTest(new TestCaller("serialize round trip",
		&EncryptedVolumeHeaderTest::TestSerializeRoundTrip));
	suite->addTest(new TestCaller("reject bad magic",
		&EncryptedVolumeHeaderTest::TestRejectBadMagic));
	suite->addTest(new TestCaller("reject future version",
		&EncryptedVolumeHeaderTest::TestRejectFutureVersion));
	suite->addTest(new TestCaller("reserved fields must be zero",
		&EncryptedVolumeHeaderTest::TestReservedFieldsMustBeZero));
	suite->addTest(new TestCaller("reject excessive KDF parameters",
		&EncryptedVolumeHeaderTest::TestRejectExcessiveKdfParameters));
	suite->addTest(new TestCaller("unlock success",
		&EncryptedVolumeHeaderTest::TestUnlockSuccess));
	suite->addTest(new TestCaller("unlock wrong passphrase",
		&EncryptedVolumeHeaderTest::TestUnlockWrongPassphrase));
	suite->addTest(new TestCaller("open wrong passphrase",
		&EncryptedVolumeHeaderTest::TestOpenWrongPassphrase));
	suite->addTest(new TestCaller("HMAC tamper detected",
		&EncryptedVolumeHeaderTest::TestHmacTamperDetected));
	suite->addTest(new TestCaller("AES-128 wrap tail must be zero",
		&EncryptedVolumeHeaderTest::TestAes128WrapTailMustBeZero));
	suite->addTest(new TestCaller("format produces different master keys",
		&EncryptedVolumeHeaderTest::TestFormatProducesDifferentMasterKeys));
	suite->addTest(new TestCaller("fuzz random headers",
		&EncryptedVolumeHeaderTest::TestFuzzRandomHeaders));
	suite->addTest(new TestCaller("torn write recovery",
		&EncryptedVolumeHeaderTest::TestTornWriteRecovery));
	suite->addTest(new TestCaller("sequence monotonic",
		&EncryptedVolumeHeaderTest::TestSequenceMonotonic));
	suite->addTest(new TestCaller("change passphrase uses selected header",
		&EncryptedVolumeHeaderTest::TestChangePassphraseUsesSelectedHeader));
	suite->addTest(new TestCaller("open does not rollback newer header",
		&EncryptedVolumeHeaderTest::TestOpenDoesNotRollbackNewerHeader));
	suite->addTest(new TestCaller("change passphrase rejects sequence overflow",
		&EncryptedVolumeHeaderTest::TestChangePassphraseRejectsSequenceOverflow));
	suite->addTest(new TestCaller("zeroization after unlock",
		&EncryptedVolumeHeaderTest::TestZeroizationAfterUnlock));

	return suite;
}


void
EncryptedVolumeHeaderTest::TestSerializeRoundTrip()
{
	const auto formatted = EncryptedVolumeHeader::Format(Bytes(kPassphrase),
		TestOptions());
	CPPUNIT_ASSERT(formatted.has_value());

	const auto parsed = EncryptedVolumeHeader::Parse(formatted->header);
	CPPUNIT_ASSERT(parsed.has_value());
	CPPUNIT_ASSERT(parsed->version == 1);
	CPPUNIT_ASSERT(parsed->sectorSize == 512);
	CPPUNIT_ASSERT(parsed->payloadOffsetSectors == 16);
	CPPUNIT_ASSERT(parsed->payloadSizeSectors == 4096);
	CPPUNIT_ASSERT(parsed->cipherId == kCipherAES256XTS);
	CPPUNIT_ASSERT(parsed->kdfId == kArgon2id);
	CPPUNIT_ASSERT(parsed->sequenceNumber == 1);
}


void
EncryptedVolumeHeaderTest::TestRejectBadMagic()
{
	auto pair = FormattedPair();
	pair.primary[0] = std::byte{'X'};

	const auto parsed = EncryptedVolumeHeader::Parse(pair.primary);
	CPPUNIT_ASSERT(!parsed.has_value());
	CPPUNIT_ASSERT(parsed.error() == B_BAD_DATA);
}


void
EncryptedVolumeHeaderTest::TestRejectFutureVersion()
{
	auto pair = FormattedPair();
	pair.primary[0x008] = std::byte{2};

	const auto parsed = EncryptedVolumeHeader::Parse(pair.primary);
	CPPUNIT_ASSERT(!parsed.has_value());
	CPPUNIT_ASSERT(parsed.error() == B_UNSUPPORTED);
}


void
EncryptedVolumeHeaderTest::TestReservedFieldsMustBeZero()
{
	auto pair = FormattedPair();
	pair.primary[0x034] = std::byte{1};

	const auto parsed = EncryptedVolumeHeader::Parse(pair.primary);
	CPPUNIT_ASSERT(!parsed.has_value());
	CPPUNIT_ASSERT(parsed.error() == B_BAD_DATA);
}


void
EncryptedVolumeHeaderTest::TestRejectExcessiveKdfParameters()
{
	auto pair = FormattedPair();
	pair.primary[0x02c] = std::byte{0xff};
	pair.primary[0x02d] = std::byte{0xff};
	pair.primary[0x02e] = std::byte{0xff};
	pair.primary[0x02f] = std::byte{0xff};

	const auto parsed = EncryptedVolumeHeader::Parse(pair.primary);
	CPPUNIT_ASSERT(!parsed.has_value());
	CPPUNIT_ASSERT(parsed.error() == B_BAD_DATA);

	const auto unlocked = EncryptedVolumeHeader::Unlock(pair.primary,
		Bytes(kPassphrase));
	CPPUNIT_ASSERT(!unlocked.has_value());
	CPPUNIT_ASSERT(unlocked.error() == B_BAD_DATA);
}


void
EncryptedVolumeHeaderTest::TestUnlockSuccess()
{
	const auto formatted = EncryptedVolumeHeader::Format(Bytes(kPassphrase),
		TestOptions());
	CPPUNIT_ASSERT(formatted.has_value());

	const auto unlocked = EncryptedVolumeHeader::Unlock(formatted->header,
		Bytes(kPassphrase));
	CPPUNIT_ASSERT(unlocked.has_value());
	CPPUNIT_ASSERT(unlocked->cipherId == kCipherAES256XTS);
	CPPUNIT_ASSERT(unlocked->masterKeyLength == 64);
	CPPUNIT_ASSERT(std::equal(unlocked->masterKey.data(),
		unlocked->masterKey.data() + unlocked->masterKeyLength,
		formatted->masterKey.data()));
}


void
EncryptedVolumeHeaderTest::TestUnlockWrongPassphrase()
{
	const auto formatted = EncryptedVolumeHeader::Format(Bytes(kPassphrase),
		TestOptions());
	CPPUNIT_ASSERT(formatted.has_value());

	AssertPermissionDenied(EncryptedVolumeHeader::Unlock(formatted->header,
		Bytes(kWrongPassphrase)));
}


void
EncryptedVolumeHeaderTest::TestOpenWrongPassphrase()
{
	auto pair = FormattedPair();

	const auto opened = EncryptedVolumeHeader::Open(pair, Bytes(kWrongPassphrase));
	CPPUNIT_ASSERT(!opened.has_value());
	CPPUNIT_ASSERT(opened.error() == B_PERMISSION_DENIED);
}


void
EncryptedVolumeHeaderTest::TestHmacTamperDetected()
{
	const auto formatted = EncryptedVolumeHeader::Format(Bytes(kPassphrase),
		TestOptions());
	CPPUNIT_ASSERT(formatted.has_value());

	HeaderBytes tampered = formatted->header;
	tampered[0x070] ^= std::byte{0x01};

	AssertPermissionDenied(EncryptedVolumeHeader::Unlock(tampered,
		Bytes(kPassphrase)));
}


void
EncryptedVolumeHeaderTest::TestAes128WrapTailMustBeZero()
{
	const auto formatted = EncryptedVolumeHeader::Format(Bytes(kPassphrase),
		TestOptions(kCipherAES128XTS));
	CPPUNIT_ASSERT(formatted.has_value());

	HeaderBytes tampered = formatted->header;
	tampered[0x070 + 40] = std::byte{0x55};

	const auto parsed = EncryptedVolumeHeader::Parse(tampered);
	CPPUNIT_ASSERT(!parsed.has_value());
	CPPUNIT_ASSERT(parsed.error() == B_BAD_DATA);
}


void
EncryptedVolumeHeaderTest::TestFormatProducesDifferentMasterKeys()
{
	const auto first = EncryptedVolumeHeader::Format(Bytes(kPassphrase),
		TestOptions());
	const auto second = EncryptedVolumeHeader::Format(Bytes(kPassphrase),
		TestOptions());
	CPPUNIT_ASSERT(first.has_value());
	CPPUNIT_ASSERT(second.has_value());
	CPPUNIT_ASSERT(!std::equal(first->masterKey.data(),
		first->masterKey.data() + first->masterKeyLength,
		second->masterKey.data()));
}


void
EncryptedVolumeHeaderTest::TestFuzzRandomHeaders()
{
	HeaderBytes header = {};

	for (uint32_t i = 0; i < 100000; i++) {
		uint32_t value = i * 1103515245u + 12345u;
		for (std::byte& byte : header) {
			value = value * 1103515245u + 12345u;
			byte = std::byte{static_cast<unsigned char>(value >> 24)};
		}

		const auto parsed = EncryptedVolumeHeader::Parse(header);
		CPPUNIT_ASSERT(!parsed.has_value());
	}
}


void
EncryptedVolumeHeaderTest::TestTornWriteRecovery()
{
	auto pair = FormattedPair();
	HeaderBytes good = pair.primary;

	pair.primary[0x020] ^= std::byte{0x40};
	const auto primaryRecovered = EncryptedVolumeHeader::Open(pair,
		Bytes(kPassphrase));
	CPPUNIT_ASSERT(primaryRecovered.has_value());
	CPPUNIT_ASSERT(pair.primary == good);

	pair.backup[0x020] ^= std::byte{0x40};
	const auto backupRecovered = EncryptedVolumeHeader::Open(pair,
		Bytes(kPassphrase));
	CPPUNIT_ASSERT(backupRecovered.has_value());
	CPPUNIT_ASSERT(pair.backup == good);

	pair.primary[0x020] ^= std::byte{0x40};
	pair.backup[0x020] ^= std::byte{0x40};
	const auto failed = EncryptedVolumeHeader::Open(pair, Bytes(kPassphrase));
	CPPUNIT_ASSERT(!failed.has_value());
	CPPUNIT_ASSERT(failed.error() == B_BAD_DATA);
}


void
EncryptedVolumeHeaderTest::TestSequenceMonotonic()
{
	auto pair = FormattedPair();
	uint32 previousSequence = SequenceNumber(pair.primary);

	for (int32 i = 0; i < 10; i++) {
		const auto result = EncryptedVolumeHeader::ChangePassphrase(pair,
			Bytes(kPassphrase), Bytes(kNewPassphrase));
		CPPUNIT_ASSERT(result.has_value());
		CPPUNIT_ASSERT(pair.primary == pair.backup);
		const uint32 sequence = SequenceNumber(pair.primary);
		CPPUNIT_ASSERT(sequence > previousSequence);
		previousSequence = sequence;

		const auto restored = EncryptedVolumeHeader::ChangePassphrase(pair,
			Bytes(kNewPassphrase), Bytes(kPassphrase));
		CPPUNIT_ASSERT(restored.has_value());
		CPPUNIT_ASSERT(pair.primary == pair.backup);
		previousSequence = SequenceNumber(pair.primary);
	}
}


void
EncryptedVolumeHeaderTest::TestChangePassphraseUsesSelectedHeader()
{
	auto pair = FormattedPair();
	HeaderBytes stalePrimary = pair.primary;

	const auto rewrapped = EncryptedVolumeHeader::ChangePassphrase(pair,
		Bytes(kPassphrase), Bytes(kPassphrase));
	CPPUNIT_ASSERT(rewrapped.has_value());
	const uint32 backupSequence = SequenceNumber(pair.backup);
	CPPUNIT_ASSERT(backupSequence > SequenceNumber(stalePrimary));

	pair.primary = stalePrimary;
	const auto changed = EncryptedVolumeHeader::ChangePassphrase(pair,
		Bytes(kPassphrase), Bytes(kPassphrase));
	CPPUNIT_ASSERT(changed.has_value());
	CPPUNIT_ASSERT(pair.primary == pair.backup);
	CPPUNIT_ASSERT(SequenceNumber(pair.primary) > backupSequence);
}


void
EncryptedVolumeHeaderTest::TestOpenDoesNotRollbackNewerHeader()
{
	auto pair = FormattedPair();
	const HeaderBytes stalePrimary = pair.primary;

	const auto changed = EncryptedVolumeHeader::ChangePassphrase(pair,
		Bytes(kPassphrase), Bytes(kNewPassphrase));
	CPPUNIT_ASSERT(changed.has_value());
	const HeaderBytes newerBackup = pair.backup;
	CPPUNIT_ASSERT(SequenceNumber(newerBackup) > SequenceNumber(stalePrimary));

	pair.primary = stalePrimary;
	const auto openedOld = EncryptedVolumeHeader::Open(pair, Bytes(kPassphrase));
	CPPUNIT_ASSERT(openedOld.has_value());
	CPPUNIT_ASSERT(pair.primary == stalePrimary);
	CPPUNIT_ASSERT(pair.backup == newerBackup);

	const auto openedNew = EncryptedVolumeHeader::Open(pair,
		Bytes(kNewPassphrase));
	CPPUNIT_ASSERT(openedNew.has_value());
	CPPUNIT_ASSERT(pair.primary == newerBackup);
	CPPUNIT_ASSERT(pair.backup == newerBackup);
}


void
EncryptedVolumeHeaderTest::TestChangePassphraseRejectsSequenceOverflow()
{
	auto pair = FormattedPair();
	pair.primary[0x0b8] = std::byte{0xff};
	pair.primary[0x0b9] = std::byte{0xff};
	pair.primary[0x0ba] = std::byte{0xff};
	pair.primary[0x0bb] = std::byte{0xff};
	RecomputeHeaderMac(pair.primary, Bytes(kPassphrase));
	pair.backup = pair.primary;

	const auto changed = EncryptedVolumeHeader::ChangePassphrase(pair,
		Bytes(kPassphrase), Bytes(kNewPassphrase));
	CPPUNIT_ASSERT(!changed.has_value());
	CPPUNIT_ASSERT(changed.error() == B_BAD_VALUE);
	CPPUNIT_ASSERT(SequenceNumber(pair.primary) == UINT32_MAX);
	CPPUNIT_ASSERT(pair.primary == pair.backup);
}


void
EncryptedVolumeHeaderTest::TestZeroizationAfterUnlock()
{
	const auto formatted = EncryptedVolumeHeader::Format(Bytes(kPassphrase),
		TestOptions());
	CPPUNIT_ASSERT(formatted.has_value());

	const auto unlocked = EncryptedVolumeHeader::Unlock(formatted->header,
		Bytes(kPassphrase));
	CPPUNIT_ASSERT(unlocked.has_value());

	const auto derived = EncryptedVolumeHeader::DebugLastDerivedBuffer();
	CPPUNIT_ASSERT(derived.size() == 64);
	CPPUNIT_ASSERT(std::all_of(derived.begin(), derived.end(),
		[](std::byte byte) { return byte == std::byte{0}; }));
}
