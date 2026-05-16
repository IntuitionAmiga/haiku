/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <unistd.h>


namespace {

struct CommandResult {
	int exitCode = -1;
	std::string output;
};


std::string
CryptvolPath()
{
	const char* path = std::getenv("CRYPTVOL_TEST_BINARY");
	return path != nullptr && path[0] != '\0' ? path : "cryptvol";
}


std::string
ShellQuote(std::string_view value)
{
	std::string quoted = "'";
	for (const char ch : value) {
		if (ch == '\'')
			quoted += "'\\''";
		else
			quoted += ch;
	}
	quoted += "'";
	return quoted;
}


CommandResult
RunCommand(std::string_view stdinText, std::string_view arguments)
{
	const std::string command = "printf %s " + ShellQuote(stdinText)
		+ " | " + ShellQuote(CryptvolPath()) + " " + std::string(arguments)
		+ " 2>&1";

	FILE* pipe = popen(command.c_str(), "r");
	if (pipe == nullptr)
		return {-1, std::strerror(errno)};

	CommandResult result;
	char buffer[512];
	while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
		result.output += buffer;

	const int status = pclose(pipe);
	result.exitCode = status == 0 ? 0 : 1;
	return result;
}


std::string
TempImagePath(const char* suffix)
{
	std::string path = "/tmp/cryptvol_cli_test_";
	path += suffix;
	path += "_XXXXXX";
	char mutablePath[128];
	std::snprintf(mutablePath, sizeof(mutablePath), "%s", path.c_str());
	const int fd = mkstemp(mutablePath);
	if (fd < 0) {
		std::fprintf(stderr, "mkstemp failed: %s\n", std::strerror(errno));
		std::abort();
	}
	close(fd);
	unlink(mutablePath);
	return mutablePath;
}


bool
Contains(std::string_view haystack, std::string_view needle)
{
	return haystack.find(needle) != std::string_view::npos;
}


void
AssertSuccess(const CommandResult& result, const char* command)
{
	if (result.exitCode == 0)
		return;

	std::fprintf(stderr, "%s failed with %d:\n%s\n", command, result.exitCode,
		result.output.c_str());
	std::abort();
}


void
AssertFailure(const CommandResult& result, const char* command)
{
	if (result.exitCode != 0)
		return;

	std::fprintf(stderr, "%s unexpectedly succeeded:\n%s\n", command,
		result.output.c_str());
	std::abort();
}


void
AssertContains(std::string_view output, std::string_view expected)
{
	if (Contains(output, expected))
		return;

	std::fprintf(stderr, "missing expected output '%s' in:\n%s\n",
		std::string(expected).c_str(), std::string(output).c_str());
	std::abort();
}


void
TestCreateAes128Info()
{
	const std::string image = TempImagePath("aes128");
	AssertSuccess(RunCommand("passphrase\n", "create --size 8M --cipher "
		"aes128-xts " + ShellQuote(image)), "create aes128");

	const CommandResult info = RunCommand("", "info " + ShellQuote(image));
	AssertSuccess(info, "info aes128");
	AssertContains(info.output, "version: 1");
	AssertContains(info.output, "cipher: 1 (AES-128-XTS)");

	unlink(image.c_str());
}


void
TestCreateAes256Info()
{
	const std::string image = TempImagePath("aes256");
	AssertSuccess(RunCommand("passphrase\n", "create --size 8M --cipher "
		"aes256-xts " + ShellQuote(image)), "create aes256");

	const CommandResult info = RunCommand("", "info " + ShellQuote(image));
	AssertSuccess(info, "info aes256");
	AssertContains(info.output, "version: 1");
	AssertContains(info.output, "cipher: 2 (AES-256-XTS)");

	unlink(image.c_str());
}


void
TestChangePassphrase()
{
	const std::string image = TempImagePath("change");
	AssertSuccess(RunCommand("old passphrase\n", "create --size 8M --cipher "
		"aes256-xts " + ShellQuote(image)), "create before change");

	AssertSuccess(RunCommand("old passphrase\nnew passphrase\n",
		"change-passphrase " + ShellQuote(image)), "change passphrase");
	AssertFailure(RunCommand("old passphrase\nnext passphrase\n",
		"change-passphrase " + ShellQuote(image)), "old passphrase rejected");
	AssertSuccess(RunCommand("new passphrase\nnext passphrase\n",
		"change-passphrase " + ShellQuote(image)), "new passphrase accepted");

	const CommandResult dump = RunCommand("", "dump-header " + ShellQuote(image));
	AssertSuccess(dump, "dump-header after change");
	AssertContains(dump.output, "sequence_number: 3");

	unlink(image.c_str());
}


void
TestDumpHeader()
{
	const std::string image = TempImagePath("dump");
	AssertSuccess(RunCommand("passphrase\n", "create --size 8M --cipher "
		"aes128-xts " + ShellQuote(image)), "create before dump");

	const CommandResult dump = RunCommand("", "dump-header " + ShellQuote(image));
	AssertSuccess(dump, "dump-header");
	AssertContains(dump.output, "magic: HAIKUENC");
	AssertContains(dump.output, "payload_offset_sectors: 16");

	unlink(image.c_str());
}

} // namespace


int
main()
{
	TestCreateAes128Info();
	TestCreateAes256Info();
	TestChangePassphrase();
	TestDumpHeader();
	return 0;
}
