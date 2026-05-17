/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef _PRIVATE_ENCRYPTED_HOME_SETTINGS_FORMAT_H
#define _PRIVATE_ENCRYPTED_HOME_SETTINGS_FORMAT_H


#include <array>
#include <string_view>


namespace BPrivate::EncryptedHome::settings {

inline constexpr const char kBootSettingsPath[]
	= "/boot/system/settings/encrypted_home";
inline constexpr const char kTargetSettingsDirectory[] = "system/settings";
inline constexpr const char kSettingsFileName[] = "encrypted_home";
inline constexpr const char kTargetSettingsPath[]
	= "system/settings/encrypted_home";

inline constexpr const char kEnabledKey[] = "enabled";
inline constexpr const char kEnabledTrueValue[] = "true";
inline constexpr const char kEnabledFalseValue[] = "false";
inline constexpr const char kVolumeUuidKey[] = "volume_uuid";

struct SettingsField {
	std::string_view name;
	std::string_view required;
	std::string_view description;
};

inline constexpr std::array<SettingsField, 2> kSettingsFields = {{
	{kEnabledKey, "yes", "Boolean; true means unlock /boot/home at boot"},
	{kVolumeUuidKey, "when enabled is true",
		"Lowercase hexadecimal 128-bit encrypted-home volume UUID"},
}};

} // namespace BPrivate::EncryptedHome::settings


#endif	// _PRIVATE_ENCRYPTED_HOME_SETTINGS_FORMAT_H
