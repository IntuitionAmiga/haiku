/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedHomeDocs.h"

#include <iostream>
#include <string_view>


using namespace BPrivate::EncryptedHome::Docs;


int
main(int argc, char** argv)
{
	const std::string_view mode = argc > 1 ? argv[1] : "header-format";
	if (mode == "header-format") {
		std::cout << GenerateHeaderFormatMarkdown();
		return 0;
	}
	if (mode == "supported-architectures") {
		std::cout << GenerateSupportedArchitecturesMarkdown();
		return 0;
	}

	std::cerr << "usage: encrypted_home_docs_gen "
		"[header-format|supported-architectures]\n";
	return 1;
}
