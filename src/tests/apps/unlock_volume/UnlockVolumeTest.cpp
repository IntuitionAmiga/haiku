/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "UnlockVolumeSupport.h"

#include <cstdio>

#include <SupportDefs.h>


namespace {

using BPrivate::EncryptedHome::Unlock::EncryptedHomeSettings;
using BPrivate::EncryptedHome::Unlock::ParseSettings;
using BPrivate::EncryptedHome::Unlock::SettingsRequireUnlock;

constexpr status_t kOk = 0;


bool
Expect(bool condition, const char* message)
{
	if (!condition)
		std::fprintf(stderr, "FAIL: %s\n", message);
	return condition;
}


bool
TestSettingsParser()
{
	EncryptedHomeSettings settings;
	bool ok = true;
	ok &= Expect(ParseSettings(
			"enabled true\n"
			"volume_uuid 00112233445566778899aabbccddeeff\n",
			settings) == kOk,
		"valid encrypted-home settings are parsed");
	ok &= Expect(settings.enabled, "enabled flag is stored");
	ok &= Expect(settings.volumeUuid[0] == std::byte{0x00}
			&& settings.volumeUuid[15] == std::byte{0xff},
		"volume UUID hex is decoded");

	ok &= Expect(ParseSettings("enabled false\n", settings) == kOk,
		"disabled settings file is parsed");
	ok &= Expect(!settings.enabled,
		"disabled settings file does not request unlock");
	ok &= Expect(ParseSettings(
			"enabled true\nvolume_uuid not-a-uuid\n", settings)
				== B_BAD_VALUE,
		"malformed UUID is rejected");
	ok &= Expect(ParseSettings(
			"enabled true\nvolume_uuid 00112233445566778899aabbccddeef\n",
			settings) == B_BAD_VALUE,
		"short UUID is rejected");
	return ok;
}


bool
TestFastPath()
{
	EncryptedHomeSettings settings;
	bool ok = true;
	ok &= Expect(!SettingsRequireUnlock(B_ENTRY_NOT_FOUND, settings),
		"missing settings file exits through fast path");
	ok &= Expect(ParseSettings("enabled false\n", settings) == kOk,
		"disabled settings parses");
	ok &= Expect(!SettingsRequireUnlock(kOk, settings),
		"disabled settings exits through fast path");
	ok &= Expect(ParseSettings(
			"enabled true\n"
			"volume_uuid 00112233445566778899aabbccddeeff\n",
			settings) == kOk,
		"enabled settings parses");
	ok &= Expect(SettingsRequireUnlock(kOk, settings),
		"enabled settings requires unlock");
	return ok;
}


} // namespace


int
main()
{
	bool ok = true;
	ok &= TestSettingsParser();
	ok &= TestFastPath();
	return ok ? 0 : 1;
}
