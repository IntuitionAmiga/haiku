/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedHomeDocs.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>


namespace {

std::string
ReadFile(const char* path)
{
	std::ifstream file(path);
	std::ostringstream contents;
	contents << file.rdbuf();
	return contents.str();
}


std::string
SourceRoot()
{
	const std::string file = __FILE__;
	const std::string suffix
		= "src/tests/tools/encrypted_home_docs_gen/TestDocsMatchSource.cpp";
	const size_t suffixOffset = file.rfind(suffix);
	if (suffixOffset != std::string::npos)
		return file.substr(0, suffixOffset);
	return "";
}


std::string
DocPath(const char* relativePath)
{
	return SourceRoot() + relativePath;
}


bool
CheckDoc(const char* path, const std::string& expected)
{
	const std::string fullPath = DocPath(path);
	const std::string actual = ReadFile(fullPath.c_str());
	if (actual == expected)
		return true;

	std::cerr << fullPath << " does not match generated output\n";
	return false;
}

} // namespace


int
main()
{
	bool ok = true;
	ok &= CheckDoc("docs/develop/security/encrypted_home/header_format.md",
		BPrivate::EncryptedHome::Docs::GenerateHeaderFormatMarkdown());
	ok &= CheckDoc("docs/develop/security/encrypted_home/supported_architectures.md",
		BPrivate::EncryptedHome::Docs::GenerateSupportedArchitecturesMarkdown());
	return ok ? 0 : 1;
}
