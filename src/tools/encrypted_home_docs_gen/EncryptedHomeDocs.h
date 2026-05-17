/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef ENCRYPTED_HOME_DOCS_H
#define ENCRYPTED_HOME_DOCS_H


#include <string>


namespace BPrivate::EncryptedHome::Docs {

std::string GenerateHeaderFormatMarkdown();
std::string GenerateIoctlFormatMarkdown();
std::string GenerateWireIdsMarkdown();
std::string GenerateSettingsFormatMarkdown();
std::string GenerateSupportedArchitecturesMarkdown();

} // namespace BPrivate::EncryptedHome::Docs


#endif	// ENCRYPTED_HOME_DOCS_H
