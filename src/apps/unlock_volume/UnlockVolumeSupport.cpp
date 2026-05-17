/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "UnlockVolumeSupport.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include <Errors.h>
#include <settings_format.h>


namespace BPrivate::EncryptedHome::Unlock {

namespace {

constexpr status_t kOk = 0;

int
HexValue(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	if (value >= 'A' && value <= 'F')
		return value - 'A' + 10;
	return -1;
}


status_t
DecodeUuid(std::string_view text, std::array<std::byte, 16>& uuid)
{
	if (text.size() != uuid.size() * 2)
		return B_BAD_VALUE;

	for (size_t index = 0; index < uuid.size(); index++) {
		const int high = HexValue(text[index * 2]);
		const int low = HexValue(text[index * 2 + 1]);
		if (high < 0 || low < 0)
			return B_BAD_VALUE;
		uuid[index] = static_cast<std::byte>((high << 4) | low);
	}
	return kOk;
}


std::string_view
Trim(std::string_view text)
{
	while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
		text.remove_prefix(1);
	while (!text.empty() && (text.back() == ' ' || text.back() == '\t'
			|| text.back() == '\r')) {
		text.remove_suffix(1);
	}
	return text;
}

} // namespace


status_t
ParseSettings(std::string_view contents, EncryptedHomeSettings& encryptedHomeSettings)
{
	encryptedHomeSettings = {};
	bool sawEnabled = false;
	bool sawUuid = false;

	while (!contents.empty()) {
		size_t end = contents.find('\n');
		std::string_view line = end == std::string_view::npos
			? contents : contents.substr(0, end);
		contents.remove_prefix(end == std::string_view::npos
			? contents.size() : end + 1);

		line = Trim(line);
		if (line.empty() || line.front() == '#')
			continue;

		const size_t space = line.find_first_of(" \t");
		std::string_view key = space == std::string_view::npos
			? line : line.substr(0, space);
		std::string_view value = space == std::string_view::npos
			? std::string_view() : Trim(line.substr(space + 1));

		if (key == settings::kEnabledKey) {
			if (value == settings::kEnabledTrueValue)
				encryptedHomeSettings.enabled = true;
			else if (value == settings::kEnabledFalseValue)
				encryptedHomeSettings.enabled = false;
			else
				return B_BAD_VALUE;
			sawEnabled = true;
		} else if (key == settings::kVolumeUuidKey) {
			status_t status = DecodeUuid(value,
				encryptedHomeSettings.volumeUuid);
			if (status != kOk)
				return status;
			sawUuid = true;
		}
	}

	if (!sawEnabled)
		return B_BAD_VALUE;
	if (encryptedHomeSettings.enabled && !sawUuid)
		return B_BAD_VALUE;
	return kOk;
}


bool
SettingsRequireUnlock(status_t settingsStatus,
	const EncryptedHomeSettings& settings)
{
	return settingsStatus == kOk && settings.enabled;
}


status_t
ReadSettingsFile(const char* path, EncryptedHomeSettings& settings)
{
	std::FILE* file = std::fopen(path, "r");
	if (file == NULL)
		return errno == 0 ? B_ENTRY_NOT_FOUND : errno;

	std::string contents;
	char buffer[256];
	for (;;) {
		size_t bytes = std::fread(buffer, 1, sizeof(buffer), file);
		if (bytes > 0)
			contents.append(buffer, bytes);
		if (bytes < sizeof(buffer))
			break;
	}
	if (std::ferror(file)) {
		status_t status = errno == 0 ? B_IO_ERROR : errno;
		std::fclose(file);
		return status;
	}
	std::fclose(file);
	return ParseSettings(contents, settings);
}


std::span<const std::byte>
PassphraseBytes(const char* text)
{
	if (text == NULL)
		return {};
	return {reinterpret_cast<const std::byte*>(text), std::strlen(text)};
}

} // namespace BPrivate::EncryptedHome::Unlock
