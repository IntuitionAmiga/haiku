/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef UNLOCK_VOLUME_SUPPORT_H
#define UNLOCK_VOLUME_SUPPORT_H


#include <array>
#include <cstddef>
#include <span>
#include <string_view>

#include <SupportDefs.h>


namespace BPrivate::EncryptedHome::Unlock {

struct EncryptedHomeSettings {
	bool enabled = false;
	std::array<std::byte, 16> volumeUuid = {};
};

status_t ParseSettings(std::string_view contents,
	EncryptedHomeSettings& settings);
bool SettingsRequireUnlock(status_t settingsStatus,
	const EncryptedHomeSettings& settings);
status_t ReadSettingsFile(const char* path, EncryptedHomeSettings& settings);
std::span<const std::byte> PassphraseBytes(const char* text);

} // namespace BPrivate::EncryptedHome::Unlock


#endif	// UNLOCK_VOLUME_SUPPORT_H
