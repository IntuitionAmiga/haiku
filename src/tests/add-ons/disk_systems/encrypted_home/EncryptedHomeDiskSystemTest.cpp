/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <encrypted_home_disk_system.h>

#include <stdio.h>
#include <string.h>

#include <Errors.h>


using namespace BPrivate::EncryptedHome;


static bool
Expect(bool condition, const char* message)
{
	if (!condition)
		fprintf(stderr, "FAIL: %s\n", message);
	return condition;
}


static void
WriteLE32(char* buffer, size_t offset, uint32 value)
{
	buffer[offset] = static_cast<char>(value & 0xff);
	buffer[offset + 1] = static_cast<char>((value >> 8) & 0xff);
	buffer[offset + 2] = static_cast<char>((value >> 16) & 0xff);
	buffer[offset + 3] = static_cast<char>((value >> 24) & 0xff);
}


static void
WriteLE64(char* buffer, size_t offset, uint64 value)
{
	WriteLE32(buffer, offset, static_cast<uint32>(value));
	WriteLE32(buffer, offset + 4, static_cast<uint32>(value >> 32));
}


int
main()
{
	char header[4096] = {};
	memcpy(header, kEncryptedHomeMagic, kEncryptedHomeMagicSize);

	bool ok = true;
	ok &= Expect(HasEncryptedHomeMagic(header, sizeof(header)),
		"encrypted-home magic is recognized");

	header[0] = 'X';
	ok &= Expect(!HasEncryptedHomeMagic(header, sizeof(header)),
		"non-matching magic is rejected");

	ok &= Expect(!HasEncryptedHomeMagic(header, kEncryptedHomeMagicSize - 1),
		"short buffers are rejected");
	ok &= Expect(!EncryptedHomePayloadSizeValid(0),
		"zero-sized encrypted payloads are rejected");
	ok &= Expect(EncryptedHomePayloadSizeValid(1),
		"non-zero encrypted payloads are accepted");
	ok &= Expect(EncryptedHomePayloadFitsPartition(8, 512, 16 * 512 + 8 * 512),
		"payload size fitting the partition is accepted");
	ok &= Expect(!EncryptedHomePayloadFitsPartition(9, 512,
			16 * 512 + 8 * 512),
		"payload size larger than the partition is rejected during identify");

	memcpy(header, kEncryptedHomeMagic, kEncryptedHomeMagicSize);
	WriteLE32(header, 0x0c, 512);
	WriteLE64(header, 0x10, kEncryptedHomePayloadOffsetSectors);
	WriteLE64(header, 0x18, 8);
	EncryptedHomeHeaderProbe headerProbe;
	ok &= Expect(!EncryptedHomeParseHeaderProbe(header, sizeof(header),
			16 * 512 + 8 * 512, 512, &headerProbe),
		"probe rejects a magic-bearing header with invalid structural fields");

	WriteLE32(header, 0x08, 1);
	WriteLE32(header, 0x20, kEncryptedHomeCipherAES256XTS);
	WriteLE32(header, 0x24, kEncryptedHomeKdfArgon2id);
	WriteLE32(header, 0x28, 3);
	WriteLE32(header, 0x2c, 65536);
	WriteLE32(header, 0x30, 4);
	WriteLE32(header, 0xb8, 1);
	ok &= Expect(EncryptedHomeParseHeaderProbe(header, sizeof(header),
			16 * 512 + 8 * 512, 512, &headerProbe),
		"backup header probe accepts a matching sector-size slot");
	ok &= Expect(!EncryptedHomeParseHeaderProbe(header, sizeof(header),
			16 * 512 + 8 * 512, 4096, &headerProbe),
		"backup header probe rejects a mismatched sector-size slot");
	ok &= Expect(EncryptedHomeBackupHeaderOffset(512) == 8 * 512,
		"512-byte backup header offset is sector 8");
	ok &= Expect(EncryptedHomeBackupHeaderOffset(4096) == 8 * 4096,
		"4 KiB backup header offset is sector 8");

	ok &= Expect(strcmp(kEncryptedHomeDiskSystemShortName, "encrypted_home")
			== 0,
		"disk-system short name is stable");
	ok &= Expect(strcmp(kEncryptedHomeDiskSystemPrettyName, "Encrypted Home")
			== 0,
		"disk-system pretty name is stable");
	ok &= Expect(!EncryptedHomeSupportsInitializing(),
		"DriveSetup initialization is disabled for v1");
	ok &= Expect(EncryptedHomeValidateInitialize() == B_NOT_SUPPORTED,
		"initialization validation returns B_NOT_SUPPORTED");
	ok &= Expect(EncryptedHomeMountUnsupported() == B_NOT_SUPPORTED,
		"mounting encrypted-home headers fails cleanly");

	return ok ? 0 : 1;
}
