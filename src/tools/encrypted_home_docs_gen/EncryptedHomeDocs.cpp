/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedHomeDocs.h"

#include <header_layout.h>

#include <fstream>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <vector>


namespace BPrivate::EncryptedHome::Docs {
namespace {

using BPrivate::EncryptedHome::wire::HeaderField;


void
WriteHex(std::ostringstream& out, std::size_t value)
{
	out << "0x" << std::hex << std::setw(3) << std::setfill('0') << value
		<< std::dec << std::setfill(' ');
}


void
WriteFieldRow(std::ostringstream& out, const HeaderField& field)
{
	out << "| ";
	WriteHex(out, field.offset);
	out << " | " << field.size << " | `" << field.name << "` | "
		<< field.description << " |\n";
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
