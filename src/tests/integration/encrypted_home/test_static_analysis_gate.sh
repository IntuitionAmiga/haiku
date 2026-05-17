#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

tmp=${TMPDIR:-/tmp}/encrypted_home_static_gate_test.$$
trap 'rm -rf "$tmp"' EXIT INT TERM

assert_pass()
{
	"$@" >/dev/null 2>&1 || {
		printf 'expected pass: %s\n' "$*" >&2
		exit 1
	}
}

assert_fail()
{
	if "$@" >/dev/null 2>&1; then
		printf 'expected failure: %s\n' "$*" >&2
		exit 1
	fi
}

make_tree()
{
	local root=$1
	rm -rf "$root"
	mkdir -p \
		"$root/src/libs/encrypted_home" \
		"$root/src/apps/unlock_volume" \
		"$root/src/add-ons/kernel/drivers/disk/virtual/encrypted_home" \
		"$root/src/add-ons/kernel/file_systems/encrypted_home" \
		"$root/src/tools/encrypted_home_docs_gen" \
		"$root/src/tests/libs/encrypted_home"

	printf 'void f() { OPENSSL_cleanse(0, 0); }\n' \
		>"$root/src/libs/encrypted_home/clean.cpp"
	printf '#include <KernelExport.h>\n' \
		>"$root/src/add-ons/kernel/drivers/disk/virtual/encrypted_home/driver.cpp"
	printf '#include <KernelExport.h>\n' \
		>"$root/src/add-ons/kernel/file_systems/encrypted_home/fs.cpp"
	printf 'void test() {}\n' \
		>"$root/src/tests/libs/encrypted_home/Test.cpp"
	printf 'void doc() {}\n' \
		>"$root/src/tools/encrypted_home_docs_gen/doc.cpp"
}

make_fake_tool()
{
	local path=$1
	local name=$2

	printf '#!/bin/sh\nprintf "%%s %%s\\n" %s "$*" >>"$STATIC_GATE_TOOL_LOG"\n' \
		"$name" >"$path/$name"
	chmod +x "$path/$name"
}

mkdir -p "$tmp"
root="$tmp/root"
make_tree "$root"

assert_pass "$script_dir/static_analysis_gate.sh" --root "$root" --policy-only

mkdir -p "$tmp/no-tools"
PATH="$tmp/no-tools" assert_fail "$script_dir/static_analysis_gate.sh" \
	--root "$root" --policy-only

printf '#include <span>\n' \
	>"$root/src/add-ons/kernel/drivers/disk/virtual/encrypted_home/driver.cpp"
assert_fail "$script_dir/static_analysis_gate.sh" --root "$root" --policy-only
make_tree "$root"

printf '#include <span>\n' \
	>"$root/src/add-ons/kernel/file_systems/encrypted_home/fs.cpp"
assert_fail "$script_dir/static_analysis_gate.sh" --root "$root" --policy-only
make_tree "$root"

printf 'void f() { const char* master_key = "x"; debug_printf("%s", master_key); }\n' \
	>"$root/src/add-ons/kernel/file_systems/encrypted_home/fs.cpp"
assert_fail "$script_dir/static_analysis_gate.sh" --root "$root" --policy-only
make_tree "$root"

printf 'void f() { char passphrase[32]; memset(passphrase, 0, sizeof(passphrase)); }\n' \
	>"$root/src/tools/encrypted_home_docs_gen/doc.cpp"
assert_fail "$script_dir/static_analysis_gate.sh" --root "$root" --policy-only
make_tree "$root"

printf 'void f() { char passphrase[32]; memset(passphrase, 0, sizeof(passphrase)); }\n' \
	>"$root/src/libs/encrypted_home/clean.cpp"
assert_fail "$script_dir/static_analysis_gate.sh" --root "$root" --policy-only
make_tree "$root"

printf 'void f() { const char* master_key = "x"; debug_printf("%s", master_key); }\n' \
	>"$root/src/apps/unlock_volume/log.cpp"
assert_fail "$script_dir/static_analysis_gate.sh" --root "$root" --policy-only
make_tree "$root"

printf 'void f() { BMessage message; message.AddString("passphrase", "secret"); }\n' \
	>"$root/src/apps/unlock_volume/message.cpp"
assert_fail "$script_dir/static_analysis_gate.sh" --root "$root" --policy-only
make_tree "$root"

fakebin="$tmp/fakebin"
tool_log="$tmp/tool.log"
build_dir="$root/generated.x86_64"
compile_commands="$build_dir/compile_commands.json"
mkdir -p "$fakebin"
mkdir -p "$build_dir"
for tool in clang-tidy analyze-build cppcheck; do
	make_fake_tool "$fakebin" "$tool"
done
printf '[{"directory":"%s","command":"cc -c ../src/libs/encrypted_home/clean.cpp","file":"../src/libs/encrypted_home/clean.cpp"},{"directory":"%s","command":"cc -c src/apps/unrelated.cpp","file":"src/apps/unrelated.cpp"}]\n' \
	"$build_dir" \
	"$root" >"$compile_commands"
STATIC_GATE_TOOL_LOG="$tool_log" PATH="$fakebin:$PATH" assert_pass \
	"$script_dir/static_analysis_gate.sh" --root "$root" \
	--compile-commands "$compile_commands"
for tool in clang-tidy analyze-build cppcheck; do
	grep -q "^$tool " "$tool_log" || {
		printf 'expected analyzer invocation: %s\n' "$tool" >&2
		exit 1
	}
done
if grep -q "$compile_commands" "$tool_log"; then
	printf 'expected analyzers to use a filtered compile database\n' >&2
	exit 1
fi
if ! grep -q "$root/src/libs/encrypted_home/clean.cpp" "$tool_log"; then
	printf 'expected clang-tidy to receive normalized encrypted-home file\n' >&2
	exit 1
fi
rm -f "$tool_log"
(
	cd "$build_dir"
	STATIC_GATE_TOOL_LOG="$tool_log" PATH="$fakebin:$PATH" assert_pass \
		"$script_dir/static_analysis_gate.sh" --root "$root" \
			--compile-commands compile_commands.json
)
if ! grep -q "$root/src/libs/encrypted_home/clean.cpp" "$tool_log"; then
	printf 'expected relative compile database path to work from build directory\n' >&2
	exit 1
fi
rm -f "$tool_log"
(
	cd "$root"
	STATIC_GATE_TOOL_LOG="$tool_log" PATH="$fakebin:$PATH" assert_pass \
		"$script_dir/static_analysis_gate.sh" --root . \
			--compile-commands generated.x86_64/compile_commands.json
)
if ! grep -q "$root/src/libs/encrypted_home/clean.cpp" "$tool_log"; then
	printf 'expected relative root path to match compile database sources\n' >&2
	exit 1
fi
rm -f "$tool_log"
STATIC_GATE_TOOL_LOG="$tool_log" PATH="$fakebin:$PATH" assert_pass \
	"$script_dir/static_analysis_gate.sh" --root "$root" \
	--tool-presence-only --compile-commands "$compile_commands"
if [ -e "$tool_log" ]; then
	printf 'expected tool presence check not to run analyzers\n' >&2
	exit 1
fi

printf 'status: pass static-analysis-gate-self-test\n'
