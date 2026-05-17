#!/bin/sh

set -eu

ehg_die()
{
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

ehg_note()
{
	printf '%s\n' "$*"
}

ehg_require_file()
{
	[ -e "$1" ] || ehg_die "missing required path: $1"
}

ehg_require_absent()
{
	[ ! -e "$1" ] || ehg_die "path must not be present: $1"
}

ehg_require_contains()
{
	local path=$1
	local pattern=$2

	ehg_require_file "$path"
	grep -F -- "$pattern" "$path" >/dev/null \
		|| ehg_die "$path does not contain: $pattern"
}

ehg_require_strings_contains()
{
	local path=$1
	local pattern=$2

	ehg_require_file "$path"
	strings "$path" | grep -F -- "$pattern" >/dev/null \
		|| ehg_die "$path strings do not contain: $pattern"
}

ehg_require_command()
{
	command -v "$1" >/dev/null 2>&1 || ehg_die "missing required command: $1"
}

ehg_status()
{
	printf 'status: %s %s\n' "$1" "$2"
}
