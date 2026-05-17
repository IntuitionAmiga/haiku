#!/bin/sh

set -eu

usage()
{
	cat <<'USAGE'
usage: static_analysis_gate.sh [--root <haiku-tree>] [--compile-commands <file>]
                               [--policy-only] [--tool-presence-only]

Runs the local encrypted-home security gate. The policy-only mode executes
project-specific source checks and is suitable for fast self-tests.
tool-presence-only also verifies the local analyzer toolchain. A full analyzer
run requires --compile-commands.
USAGE
}

root=
compile_commands=
policy_only=0
tool_presence_only=0

while [ $# -gt 0 ]; do
	case "$1" in
		--root)
			[ $# -ge 2 ] || {
				usage >&2
				exit 2
			}
			root=$2
			shift 2
			;;
		--compile-commands)
			[ $# -ge 2 ] || {
				usage >&2
				exit 2
			}
			compile_commands=$2
			shift 2
			;;
		--policy-only)
			policy_only=1
			shift
			;;
		--tool-presence-only)
			tool_presence_only=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			usage >&2
			exit 2
			;;
	esac
done

if [ -z "$root" ]; then
	root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
fi

[ -d "$root" ] || {
	printf 'static-analysis-gate: root does not exist: %s\n' "$root" >&2
	exit 2
}
root=$(CDPATH= cd -- "$root" && pwd)

case "$compile_commands" in
	""|/*)
		;;
	*)
		compile_commands=$(CDPATH= cd -- "$(dirname -- "$compile_commands")" \
			&& pwd)/$(basename -- "$compile_commands")
		;;
esac

cd "$root"

failures=0

gate_fail()
{
	printf 'static-analysis-gate: fail: %s\n' "$1" >&2
	failures=$((failures + 1))
}

require_command()
{
	command -v "$1" >/dev/null 2>&1 || gate_fail "missing required tool: $1"
}

require_command rg

work_dir=${TMPDIR:-/tmp}/encrypted-home-static-gate.$$
cleanup()
{
	rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM
mkdir -p "$work_dir"

existing_scope_paths()
{
	for path in \
		src/libs/encrypted_home \
		src/bin/cryptvol \
		src/apps/unlock_volume \
		src/apps/installer/EncryptedHomeProvisioner.cpp \
			src/apps/installer/EncryptedHomeProvisioner.h \
			src/apps/installer/InstallerWindow.cpp \
			src/apps/installer/InstallerWindow.h \
			src/apps/installer/WorkerThread.cpp \
			src/apps/installer/WorkerThread.h \
			src/add-ons/kernel/drivers/disk/virtual/encrypted_home \
			src/add-ons/kernel/file_systems/encrypted_home \
			src/add-ons/disk_systems/encrypted_home \
			src/tools/encrypted_home_docs_gen \
			src/tests/libs/encrypted_home \
			src/tests/bin/cryptvol \
			src/tests/apps/unlock_volume \
		src/tests/add-ons/kernel/drivers/disk/virtual/encrypted_home \
		src/tests/add-ons/disk_systems/encrypted_home \
		src/tests/tools/encrypted_home_docs_gen
	do
		[ -e "$path" ] && printf '%s\n' "$path"
	done
	return 0
}

existing_kernel_scope_paths()
{
	for path in \
		src/add-ons/kernel/drivers/disk/virtual/encrypted_home \
		src/add-ons/kernel/file_systems/encrypted_home
	do
		[ -e "$path" ] && printf '%s\n' "$path"
	done
	return 0
}

compile_database_scope_files()
{
	local selected_records=$1
	local directory
	local file
	local file_path
	local rel
	local scope

	awk '
		BEGIN {
			RS = "},"
		}
		{
			directory = ""
			file = ""
			if (match($0, /"directory"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
				directory = substr($0, RSTART, RLENGTH)
				sub(/^"directory"[[:space:]]*:[[:space:]]*"/, "", directory)
				sub(/"$/, "", directory)
			}
			if (match($0, /"file"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
				file = substr($0, RSTART, RLENGTH)
				sub(/^"file"[[:space:]]*:[[:space:]]*"/, "", file)
				sub(/"$/, "", file)
			}
			if (directory != "" && file != "") {
				print directory "\t" file
			}
		}
	' "$compile_commands" | while IFS='	' read -r directory file; do
		case "$file" in
			/*)
				file_path=$file
				;;
			*)
				[ -d "$directory" ] || continue
				file_path=$(CDPATH= cd -- "$directory" && pwd)/$file
				;;
		esac

		[ -f "$file_path" ] || continue
		file_path=$(CDPATH= cd -- "$(dirname -- "$file_path")" && pwd)/$(basename -- "$file_path")
		rel=$file_path
		case "$rel" in
			"$root"/*)
				rel=${rel#"$root"/}
				;;
		esac

			for scope in $scope_paths; do
				case "$rel" in
					"$scope"|"$scope"/*)
						printf '%s	%s\n' "$directory" "$file" >>"$selected_records"
						printf '%s\n' "$file_path"
						break
						;;
				esac
			done
	done | sort -u
}

filter_compile_database()
{
	local file_list=$1
	local output=$2

	awk -v file_list="$file_list" '
		BEGIN {
			while ((getline line < file_list) > 0)
				wanted[line] = 1
			print "["
			first = 1
			RS = "},"
			ORS = ""
		}
		{
			record = $0
			gsub(/^[[:space:]\[]*/, "", record)
			gsub(/[[:space:]\]]*$/, "", record)
			if (record == "")
				next
			if (substr(record, 1, 1) != "{")
				record = "{" record
			if (substr(record, length(record), 1) != "}")
				record = record "}"

			compact = record
			gsub(/[[:space:]]/, "", compact)
			directory = ""
			file = ""
			if (match(record, /"directory"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
				directory = substr(record, RSTART, RLENGTH)
				sub(/^"directory"[[:space:]]*:[[:space:]]*"/, "", directory)
				sub(/"$/, "", directory)
			}
			if (match(record, /"file"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
				file = substr(record, RSTART, RLENGTH)
				sub(/^"file"[[:space:]]*:[[:space:]]*"/, "", file)
				sub(/"$/, "", file)
			}
			if (wanted[directory "\t" file]) {
				if (!first)
					print ",\n"
				print record
				first = 0
			}
		}
		END {
			print "\n]\n"
		}
	' "$compile_commands" >"$output"
}

run_rg()
{
	local pattern=$1
	shift

	[ $# -gt 0 ] || return 1
	rg -n \
		--glob '*.c' \
		--glob '*.cpp' \
		--glob '*.h' \
		--glob '*.hpp' \
		--glob '!src/libs/phc_argon2/**' \
		--glob '!src/libs/openbsd_softraid_crypto/**' \
		"$pattern" "$@"
}

check_no_matches()
{
	local description=$1
	local pattern=$2
	shift 2

	local output
	if output=$(run_rg "$pattern" "$@" 2>/dev/null); then
		printf '%s\n' "$output" >&2
		gate_fail "$description"
	fi
	return 0
}

scope_paths=$(existing_scope_paths)
kernel_scope_paths=$(existing_kernel_scope_paths)
if [ -z "$scope_paths" ]; then
	gate_fail "no encrypted-home scope paths found"
else
	if [ -z "$kernel_scope_paths" ]; then
		gate_fail "no encrypted-home kernel scope paths found"
	else
		# shellcheck disable=SC2086
		check_no_matches \
			"forbidden hosted C++ headers in kernel encrypted-home code" \
			'#include[[:space:]]*<(expected|span|array|bit)>' \
			$kernel_scope_paths
	fi

	# shellcheck disable=SC2086
	check_no_matches \
		"secret-like values must not be written to formatted logs" \
		'(printf|fprintf|dprintf|syslog|debug_printf)[[:space:]]*\([^;]*(passphrase|password|key|kek|mac|secret|master_key)' \
		$scope_paths

	# shellcheck disable=SC2086
	check_no_matches \
		"secret-like values must not be cleared with memset" \
		'memset[[:space:]]*\([^;]*(passphrase|password|key|kek|mac|secret|master_key)' \
		$scope_paths

	# shellcheck disable=SC2086
	check_no_matches \
		"secrets must not be passed through BMessage fields" \
		'Add(String|Data|Flat|Message)[[:space:]]*\([^;]*(passphrase|password|key|kek|mac|secret|master_key)' \
		$scope_paths
fi

if [ "$policy_only" -eq 0 ]; then
	require_command clang-tidy
	require_command analyze-build
	require_command cppcheck

	if [ "$tool_presence_only" -eq 0 ] && [ -z "$compile_commands" ]; then
		gate_fail "full analyzer run requires --compile-commands"
	fi

	if [ -n "$compile_commands" ]; then
		[ -f "$compile_commands" ] || gate_fail \
			"compile_commands.json not found: $compile_commands"
	fi

		if [ "$tool_presence_only" -eq 0 ] && [ "$failures" -eq 0 ] \
				&& [ -n "$compile_commands" ] && [ -f "$compile_commands" ]; then
			compile_record_list=$work_dir/compile-records.txt
			: >"$compile_record_list"
			compile_files=$(compile_database_scope_files "$compile_record_list")
			if [ -z "$compile_files" ]; then
				gate_fail "compile_commands.json contains no encrypted-home source files"
			else
				compile_file_list=$work_dir/compile-files.txt
				filtered_compile_commands=$work_dir/compile_commands.json
				printf '%s\n' "$compile_files" >"$compile_file_list"
				filter_compile_database "$compile_record_list" "$filtered_compile_commands"

			# shellcheck disable=SC2086
			clang-tidy -p "$(dirname -- "$filtered_compile_commands")" $compile_files

			# analyze-build is the Clang static analyzer entry point that consumes
			# an existing compilation database; scan-build wraps live build commands.
			analyze-build --cdb "$filtered_compile_commands" --status-bugs \
				--output "${TMPDIR:-/tmp}/encrypted-home-analyze-build.$$"

			cppcheck --enable=warning,style,performance,portability \
				--addon=cert --error-exitcode=1 \
				--project="$filtered_compile_commands"
		fi
	fi
fi

[ "$failures" -eq 0 ] || exit 1

printf 'status: pass static-analysis-gate\n'
