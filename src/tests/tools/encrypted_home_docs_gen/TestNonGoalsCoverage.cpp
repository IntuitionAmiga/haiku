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
	const std::string threatModel = ReadFile(
		DocPath("docs/develop/security/encrypted_home/threat_model.md").c_str());
	const std::string nonGoals = ReadFile(
		DocPath("docs/develop/security/encrypted_home/non_goals.md").c_str());

	const std::array<std::string_view, 7> goals = {
		"Data-area tampering",
		"Evil-maid attacks on the plaintext system partition",
		"Cold-boot RAM extraction",
		"Running malware in the user's session",
		"Physical input capture",
		"Hibernation",
		"Header rollback after passphrase change",
	};

	bool ok = true;
	for (std::string_view goal : goals) {
		if (!Contains(nonGoals, goal)) {
			std::cerr << "missing non-goal entry: " << goal << "\n";
			ok = false;
		}
		if (!Contains(threatModel, goal)) {
			std::cerr << "missing threat-model entry: " << goal << "\n";
			ok = false;
		}
	}

	return ok ? 0 : 1;
}
