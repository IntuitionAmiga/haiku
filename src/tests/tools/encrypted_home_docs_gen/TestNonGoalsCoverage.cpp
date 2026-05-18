/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <array>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>


namespace {

std::string
ReadFile(const char* path)
{
	std::ifstream file(path);
	std::ostringstream contents;
	contents << file.rdbuf();
	return contents.str();
}


bool
Contains(const std::string& text, std::string_view needle)
{
	return text.find(needle) != std::string::npos;
}


std::string
SourceRoot()
{
	const std::string file = __FILE__;
	const std::string suffix
		= "src/tests/tools/encrypted_home_docs_gen/TestNonGoalsCoverage.cpp";
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

} // namespace


int
main()
{
	const std::string securityReadme = ReadFile(
		DocPath("docs/develop/security/encrypted_home/README.md").c_str());
	const std::string userDoc = ReadFile(
		DocPath("docs/user/encrypted_home/index.md").c_str());

	struct CoverageNeedle {
		std::string_view threatModel;
		std::string_view userDoc;
	};

	const std::array<CoverageNeedle, 7> exclusions = {{
		{"Data-area tampering", "data-area tampering"},
		{"plaintext system partition", "plaintext system partition"},
		{"Cold-boot RAM extraction", "cold-boot RAM extraction"},
		{"malware in the user's session", "unlocked session"},
		{"Physical input capture", "physical input capture"},
		{"Hibernation", "hibernation"},
		{"Header rollback after passphrase change",
			"rollback after passphrase change"},
	}};

	bool ok = true;
	for (const CoverageNeedle& exclusion : exclusions) {
		if (!Contains(securityReadme, exclusion.threatModel)) {
			std::cerr << "missing security README entry: "
				<< exclusion.threatModel << "\n";
			ok = false;
		}
		if (!Contains(userDoc, exclusion.userDoc)) {
			std::cerr << "missing user-doc non-goal entry: "
				<< exclusion.userDoc << "\n";
			ok = false;
		}
	}

	return ok ? 0 : 1;
}
