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

	if [ "$name" = analyze-build ]; then
		printf '%s\n' \
			'#!/bin/sh' \
			'printf "%s %s\n" analyze-build "$*" >>"$STATIC_GATE_TOOL_LOG"' \
			'output=' \
			'while [ $# -gt 0 ]; do' \
			'	case "$1" in' \
			'		--output)' \
			'			output=$2' \
			'			shift 2' \
			'			;;' \
			'		*)' \
			'			shift' \
			'			;;' \
			'	esac' \
			'done' \
			'if [ -n "${STATIC_GATE_ANALYZE_REPORT:-}" ]; then' \
			'	report_dir=$output/scan-build-test' \
			'	mkdir -p "$report_dir"' \
			'	printf "<!-- BUGFILE %s -->\n" "$STATIC_GATE_ANALYZE_REPORT" \' \
			'		>"$report_dir/report-test.html"' \
			'fi' >"$path/$name"
	elif [ "$name" = cppcheck ]; then
		printf '%s\n' \
			'#!/bin/sh' \
			'printf "%s %s\n" cppcheck "$*" >>"$STATIC_GATE_TOOL_LOG"' \
			'if [ -n "${STATIC_GATE_EXPECT_CPPCHECK_ADDON:-}" ]; then' \
			'	found=0' \
			'	for arg do' \
			'		[ "$arg" = "$STATIC_GATE_EXPECT_CPPCHECK_ADDON" ] && found=1' \
			'	done' \
			'	if [ "$found" -eq 0 ]; then' \
			'		printf "missing exact cppcheck addon arg: %s\n" \' \
			'			"$STATIC_GATE_EXPECT_CPPCHECK_ADDON" >&2' \
			'		exit 1' \
			'	fi' \
			'fi' \
			'if [ -n "${STATIC_GATE_CPPCHECK_REPORT:-}" ]; then' \
			'	printf "%s:12:3: warning: fake cppcheck report [fake]\n" \' \
			'		"$STATIC_GATE_CPPCHECK_REPORT" >&2' \
			'fi' >"$path/$name"
	else
		printf '#!/bin/sh\nprintf "%%s %%s\\n" %s "$*" >>"$STATIC_GATE_TOOL_LOG"\n' \
			"$name" >"$path/$name"
	fi
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
if ! grep -q '^clang-tidy .*--checks=clang-analyzer-\*,bugprone-\*,cert-\*,cppcoreguidelines-\*,performance-\*,portability-\*' "$tool_log"; then
	printf 'expected clang-tidy to enable security-focused checks\n' >&2
	exit 1
fi
if ! grep -q -- '--header-filter=' "$tool_log"; then
	printf 'expected clang-tidy to suppress unrelated header diagnostics\n' >&2
	exit 1
fi
if ! grep -q '^clang-tidy .*--extra-arg=-Wno-error=unknown-warning-option .*--extra-arg=-Wno-unknown-warning-option' "$tool_log"; then
	printf 'expected clang-tidy to tolerate GCC-only warning flags\n' >&2
	exit 1
fi
if grep -q '^cppcheck .*--addon=cert' "$tool_log"; then
	printf 'did not expect cppcheck to require the proprietary CERT addon by default\n' >&2
	exit 1
fi
if grep -q '^cppcheck .*--report-type=cert-cpp-2016' "$tool_log"; then
	printf 'did not expect cppcheck to emit CERT classifications without an addon\n' >&2
	exit 1
fi
rm -f "$tool_log"
cert_addon_dir="$tmp/cert addon dir"
mkdir -p "$cert_addon_dir"
cert_addon="$cert_addon_dir/cert addon.py"
printf '# fake cert addon\n' >"$cert_addon"
CPPCHECK_CERT_ADDON="$cert_addon" \
	STATIC_GATE_EXPECT_CPPCHECK_ADDON="--addon=$cert_addon" \
	STATIC_GATE_TOOL_LOG="$tool_log" PATH="$fakebin:$PATH" assert_pass \
	"$script_dir/static_analysis_gate.sh" --root "$root" \
	--compile-commands "$compile_commands"
if ! grep -F -q -- "--addon=$cert_addon" "$tool_log"; then
	printf 'expected cppcheck to use explicit CERT addon path\n' >&2
	exit 1
fi
if ! grep -q '^cppcheck .*--report-type=cert-cpp-2016' "$tool_log"; then
	printf 'expected cppcheck to emit CERT report classifications with addon\n' >&2
	exit 1
fi
rm -f "$tool_log"
CPPCHECK_CERT_ADDON="$tmp/missing-cert.py" STATIC_GATE_TOOL_LOG="$tool_log" \
	PATH="$fakebin:$PATH" assert_fail \
	"$script_dir/static_analysis_gate.sh" --root "$root" \
	--compile-commands "$compile_commands"
rm -f "$tool_log"
STATIC_GATE_ANALYZE_REPORT="$root/headers/os/interface/LayoutBuilder.h" \
	STATIC_GATE_TOOL_LOG="$tool_log" PATH="$fakebin:$PATH" assert_pass \
	"$script_dir/static_analysis_gate.sh" --root "$root" \
	--compile-commands "$compile_commands"
rm -f "$tool_log"
STATIC_GATE_ANALYZE_REPORT="$root/src/libs/encrypted_home/clean.cpp" \
	STATIC_GATE_TOOL_LOG="$tool_log" PATH="$fakebin:$PATH" assert_fail \
	"$script_dir/static_analysis_gate.sh" --root "$root" \
	--compile-commands "$compile_commands"
if ! grep -q '^cppcheck ' "$tool_log"; then
	printf 'expected cppcheck to run after an in-scope analyzer finding\n' >&2
	exit 1
fi
rm -f "$tool_log"
STATIC_GATE_ANALYZE_REPORT="$root/generated.x86_64/../src/libs/encrypted_home/clean.cpp" \
	STATIC_GATE_TOOL_LOG="$tool_log" PATH="$fakebin:$PATH" assert_fail \
	"$script_dir/static_analysis_gate.sh" --root "$root" \
	--compile-commands "$compile_commands"
rm -f "$tool_log"
STATIC_GATE_CPPCHECK_REPORT="$root/headers/private/kernel/util/AutoLock.h" \
	STATIC_GATE_TOOL_LOG="$tool_log" PATH="$fakebin:$PATH" assert_pass \
	"$script_dir/static_analysis_gate.sh" --root "$root" \
	--compile-commands "$compile_commands"
rm -f "$tool_log"
STATIC_GATE_CPPCHECK_REPORT="$root/src/libs/encrypted_home/clean.cpp" \
	STATIC_GATE_TOOL_LOG="$tool_log" PATH="$fakebin:$PATH" assert_fail \
	"$script_dir/static_analysis_gate.sh" --root "$root" \
	--compile-commands "$compile_commands"
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
