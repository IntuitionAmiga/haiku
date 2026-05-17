/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedHomeDocs.h"

#include <encrypted_home_driver_layout.h>
#include <header_layout.h>
#include <settings_format.h>

#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <vector>


namespace BPrivate::EncryptedHome::Docs {
namespace {

using BPrivate::EncryptedHome::wire::HeaderField;


struct IdField {
	std::string_view name;
	std::uint64_t value;
	std::string_view description;
};


void
WriteHex(std::ostringstream& out, std::size_t value)
{
	out << "0x" << std::hex << std::setw(3) << std::setfill('0') << value
		<< std::dec << std::setfill(' ');
}


void
WriteValueHex(std::ostringstream& out, std::uint64_t value)
{
	out << "0x" << std::hex << value << std::dec;
}


void
WriteFieldRow(std::ostringstream& out, const HeaderField& field)
{
	out << "| ";
	WriteHex(out, field.offset);
	out << " | " << field.size << " | `" << field.name << "` | "
		<< field.description << " |\n";
}


void
WriteLayoutRow(std::ostringstream& out,
	const driver_wire::LayoutField& field)
{
	out << "| ";
	WriteHex(out, field.offset);
	out << " | " << field.size << " | `" << field.name << "` | "
		<< field.description << " |\n";
}


void
WriteIdRow(std::ostringstream& out, const IdField& field)
{
	out << "| `" << field.name << "` | " << field.value << " | ";
	WriteValueHex(out, field.value);
	out << " | " << field.description << " |\n";
}


std::string
SourceRoot()
{
	const std::string file = __FILE__;
	const std::string suffix
		= "src/tools/encrypted_home_docs_gen/EncryptedHomeDocs.cpp";
	const size_t suffixOffset = file.rfind(suffix);
	if (suffixOffset != std::string::npos)
		return file.substr(0, suffixOffset);
	return "";
}


std::string
WithoutFinalBlankLine(std::string text)
{
	if (text.size() >= 2 && text[text.size() - 1] == '\n'
		&& text[text.size() - 2] == '\n') {
		text.pop_back();
	}
	return text;
}


template<std::size_t Count>
void
WriteRequestLayout(std::ostringstream& out, std::string_view name,
	std::size_t size, const driver_wire::LayoutField (&fields)[Count])
{
	out << "## `" << name << "`\n\n";
	out << "Size: " << size << " bytes.\n\n";
	out << "| Offset | Size | Field | Description |\n";
	out << "| --- | ---: | --- | --- |\n";
	for (const driver_wire::LayoutField& field : fields)
		WriteLayoutRow(out, field);
	out << "\n";
}


std::vector<std::string>
ReadSupportedArchitectures()
{
	std::ifstream features(SourceRoot()
		+ "build/jam/encrypted_home_features.jam");
	std::string line;
	while (std::getline(features, line)) {
		const std::string prefix = "ENCRYPTED_HOME_SUPPORTED_ARCHS =";
		const size_t prefixOffset = line.find(prefix);
		if (prefixOffset == std::string::npos)
			continue;

		std::istringstream words(line.substr(prefixOffset + prefix.size()));
		std::vector<std::string> archs;
		std::string word;
		while (words >> word) {
			if (word == ";")
				break;
			archs.push_back(word);
		}
		return archs;
	}

	return {};
}


constexpr std::array<IdField, 5> kIoctlIds = {{
	{"IOCTL_ENCRYPTED_HOME_REGISTER", driver_wire::kIoctlRegister,
		"Register a backing store and publish a raw virtual device"},
	{"IOCTL_ENCRYPTED_HOME_UNREGISTER", driver_wire::kIoctlUnregister,
		"Unpublish a registered encrypted-home virtual device"},
	{"IOCTL_ENCRYPTED_HOME_UNLOCK", driver_wire::kIoctlUnlock,
		"Install an unwrapped master key into the raw virtual device"},
	{"IOCTL_ENCRYPTED_HOME_LOCK", driver_wire::kIoctlLock,
		"Drop the active XTS key from the raw virtual device"},
	{"IOCTL_ENCRYPTED_HOME_INFO", driver_wire::kIoctlInfo,
		"Return current registration and unlock state"},
}};


constexpr std::array<IdField, 2> kCipherIds = {{
	{"kCipherAES128XTS", wire::kCipherAES128XTS,
		"AES-128-XTS with a 32-byte master key"},
	{"kCipherAES256XTS", wire::kCipherAES256XTS,
		"AES-256-XTS with a 64-byte master key"},
}};


constexpr std::array<IdField, 1> kKdfIds = {{
	{"kKdfArgon2id", wire::kKdfArgon2id,
		"Argon2id password KDF"},
}};


void
WriteSupportedArchitectureRow(std::ostringstream& out, const std::string& arch)
{
	out << "| " << arch
		<< " | Supported when the OpenSSL build feature is enabled |\n";
}


} // namespace


std::string
GenerateHeaderFormatMarkdown()
{
	std::ostringstream out;
	out << "# Encrypted Home Header Format\n\n";
	out << "This file is generated from "
		"`headers/private/encrypted_home/header_layout.h`. Do not hand-edit "
		"the byte offsets in this table.\n\n";
	out << "All integer fields are little-endian. The header is "
		<< wire::kHeaderSize << " bytes. The header HMAC covers bytes [";
	WriteHex(out, 0);
	out << ", ";
	WriteHex(out, wire::kHmacCoveredEnd);
	out << ").\n\n";
	out << "| Offset | Size | Field | Description |\n";
	out << "| --- | ---: | --- | --- |\n";
	for (const HeaderField& field : wire::kHeaderFields)
		WriteFieldRow(out, field);
	out << "\nPrimary header sector: 0. Backup header sector: 8. Payload starts "
		"at sector " << wire::kPayloadOffsetSectors << ".\n";
	return out.str();
}


std::string
GenerateIoctlFormatMarkdown()
{
	std::ostringstream out;
	out << "# Encrypted Home Ioctl Format\n\n";
	out << "This file is generated from "
		"`headers/private/encrypted_home/encrypted_home_driver_layout.h`. "
		"`encrypted_home_driver.h` asserts that the compiled ioctl structs "
		"match these constants. Do not hand-edit ioctl request layouts in "
		"this table.\n\n";
	out << "All integer fields use the target ABI's normal representation. "
		"Userland and the kernel are built from the same private header.\n\n";
	WriteRequestLayout(out, "encrypted_home_ioctl_register",
		driver_wire::kRegisterSize, driver_wire::kRegisterFields);
	WriteRequestLayout(out, "encrypted_home_ioctl_unregister",
		driver_wire::kUnregisterSize, driver_wire::kUnregisterFields);
	WriteRequestLayout(out, "encrypted_home_ioctl_unlock",
		driver_wire::kUnlockSize, driver_wire::kUnlockFields);
	WriteRequestLayout(out, "encrypted_home_ioctl_info",
		driver_wire::kInfoSize, driver_wire::kInfoFields);
	return WithoutFinalBlankLine(out.str());
}


std::string
GenerateWireIdsMarkdown()
{
	std::ostringstream out;
	out << "# Encrypted Home Wire IDs\n\n";
	out << "This file is generated from private encrypted-home headers. Do "
		"not hand-edit the numeric IDs in these tables.\n\n";
	out << "## Cipher IDs\n\n";
	out << "| Name | Value | Hex | Description |\n";
	out << "| --- | ---: | ---: | --- |\n";
	for (const IdField& field : kCipherIds)
		WriteIdRow(out, field);
	out << "\n## KDF IDs\n\n";
	out << "| Name | Value | Hex | Description |\n";
	out << "| --- | ---: | ---: | --- |\n";
	for (const IdField& field : kKdfIds)
		WriteIdRow(out, field);
	out << "\n## Ioctl IDs\n\n";
	out << "| Name | Value | Hex | Description |\n";
	out << "| --- | ---: | ---: | --- |\n";
	for (const IdField& field : kIoctlIds)
		WriteIdRow(out, field);
	return out.str();
}


std::string
GenerateSettingsFormatMarkdown()
{
	std::ostringstream out;
	out << "# Encrypted Home Settings Format\n\n";
	out << "This file is generated from "
		"`headers/private/encrypted_home/settings_format.h`. Do not "
		"hand-edit the setting keys in this table.\n\n";
	out << "Boot path: `" << settings::kBootSettingsPath << "`.\n\n";
	out << "Installer target-relative directory: `"
		<< settings::kTargetSettingsDirectory << "`.\n\n";
	out << "File name: `" << settings::kSettingsFileName << "`.\n\n";
	out << "Installer target-relative path: `"
		<< settings::kTargetSettingsPath << "`.\n\n";
	out << "| Key | Required | Description |\n";
	out << "| --- | --- | --- |\n";
	for (const settings::SettingsField& field : settings::kSettingsFields) {
		out << "| `" << field.name << "` | " << field.required << " | "
			<< field.description << " |\n";
	}
	out << "\nExample:\n\n```text\n";
	out << settings::kEnabledKey << " " << settings::kEnabledTrueValue
		<< "\n";
	out << settings::kVolumeUuidKey
		<< " 00112233445566778899aabbccddeeff\n";
	out << "```\n";
	return out.str();
}


std::string
GenerateSupportedArchitecturesMarkdown()
{
	std::ostringstream out;
	out << "# Encrypted Home Supported Architectures\n\n";
	out << "The build-system source of truth is "
		"`ENCRYPTED_HOME_SUPPORTED_ARCHS` in "
		"`build/jam/encrypted_home_features.jam`.\n\n";
	out << "| Architecture | Status |\n";
	out << "| --- | --- |\n";
	for (const std::string& arch : ReadSupportedArchitectures())
		WriteSupportedArchitectureRow(out, arch);
	out << "\nOther packaging architectures skip encrypted-home targets in v1.\n";
	return out.str();
}

} // namespace BPrivate::EncryptedHome::Docs
