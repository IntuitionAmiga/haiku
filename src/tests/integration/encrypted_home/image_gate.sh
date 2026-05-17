#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/lib.sh"

usage()
{
	cat <<'USAGE'
usage: image_gate.sh <phase7|phase8>

Environment:
  HAIKU_ENCRYPTED_HOME_IMAGE_ROOT   packagefs-resolved image root for preflight
  HAIKU_ENCRYPTED_HOME_IMAGE        production image path for full gate runs
  HAIKU_ENCRYPTED_HOME_WORK_DIR     output directory for logs and dumps
  HAIKU_ENCRYPTED_HOME_PREFLIGHT_ONLY=1
                                    run only image_contents.sh against IMAGE_ROOT
USAGE
}

phase=${1:-}
[ "$phase" = phase7 ] || [ "$phase" = phase8 ] || {
	usage >&2
	exit 2
}

work_dir=${HAIKU_ENCRYPTED_HOME_WORK_DIR:-"$PWD/encrypted_home_image_gate_$phase"}
mkdir -p "$work_dir"
phase_log="$work_dir/$phase.log"
: >"$phase_log"

gate_status()
{
	ehg_status "$@" | tee -a "$phase_log"
}

run_preflight()
{
	local root=${HAIKU_ENCRYPTED_HOME_IMAGE_ROOT:-}

	[ -n "$root" ] || ehg_die \
		"HAIKU_ENCRYPTED_HOME_IMAGE_ROOT is required for preflight"
	"$script_dir/image_contents.sh" --root "$root" \
		>"$work_dir/preflight.log" 2>&1 || {
			cat "$work_dir/preflight.log" >&2
			exit 1
		}
	cat "$work_dir/preflight.log"
}

check_kvm()
{
	if [ "${HAIKU_ENCRYPTED_HOME_SELF_TEST_ASSUME_KVM:-0}" = 1 ]; then
		ehg_note "KVM check skipped by HAIKU_ENCRYPTED_HOME_SELF_TEST_ASSUME_KVM=1"
		return
	fi

	ehg_require_command qemu-system-x86_64
	[ -r /dev/kvm ] && [ -w /dev/kvm ] \
		|| ehg_die "KVM unavailable: check /dev/kvm permissions, BIOS VT-x/AMD-V, and group membership"

	if command -v kvm-ok >/dev/null 2>&1; then
		kvm-ok >/dev/null 2>&1 \
			|| ehg_die "KVM unavailable: kvm-ok reported failure"
	fi

	grep -Eq '^flags.*\b(vmx|svm)\b' /proc/cpuinfo \
		|| ehg_die "KVM unavailable: host CPU flags lack vmx/svm"
}

run_path()
{
	local run_name=$1
	local result_status=$2
	local blocking=$3
	local driver=$4
	local serial_log="$work_dir/${run_name}_serial.log"

	if [ "${HAIKU_ENCRYPTED_HOME_SELF_TEST_DRY_RUN:-0}" = 1 ]; then
		{
			printf 'dry-run: qemu-system-x86_64'
			printf ' -enable-kvm -cpu host -smp 4 -m 4G'
			printf ' -hda %s' "$HAIKU_ENCRYPTED_HOME_IMAGE"
			printf ' -display vnc=:%s' "$5"
			printf ' -serial file:%s' "$serial_log"
			printf ' # driver=%s\n' "$driver"
		} >>"$phase_log"
		gate_status "$result_status" "$run_name"
		return
	fi

	ehg_require_command expect
	[ -x "$driver" ] || ehg_die "missing executable path driver: $driver"

	if HAIKU_ENCRYPTED_HOME_IMAGE="$HAIKU_ENCRYPTED_HOME_IMAGE" \
		HAIKU_ENCRYPTED_HOME_WORK_DIR="$work_dir" \
		HAIKU_ENCRYPTED_HOME_RUN_NAME="$run_name" \
		HAIKU_ENCRYPTED_HOME_SERIAL_LOG="$serial_log" \
		"$driver" "$phase" "$run_name" >>"$phase_log" 2>&1; then
		gate_status "$result_status" "$run_name"
		return
	fi

	if [ "$blocking" = blocking ]; then
		cat "$phase_log" >&2
		ehg_die "$run_name failed"
	fi

	gate_status non-gating-diagnostic "$run_name"
}

run_preflight

if [ "${HAIKU_ENCRYPTED_HOME_PREFLIGHT_ONLY:-0}" = 1 ]; then
	gate_status pass "$phase-preflight-only"
	exit 0
fi

[ -n "${HAIKU_ENCRYPTED_HOME_IMAGE:-}" ] \
	|| ehg_die "HAIKU_ENCRYPTED_HOME_IMAGE is required for full $phase gate"
[ -e "$HAIKU_ENCRYPTED_HOME_IMAGE" ] \
	|| ehg_die "image does not exist: $HAIKU_ENCRYPTED_HOME_IMAGE"

check_kvm

case "$phase" in
	phase7)
		run_path path-a-gui pass blocking "$script_dir/path_a_gui.exp" 1
		run_path path-b-install-only pass blocking \
			"$script_dir/path_b_install_only.exp" 2
		run_path path-a-headless non-gating-diagnostic diagnostic \
			"$script_dir/path_a_headless.exp" 4
		run_path path-b-install-headless non-gating-diagnostic diagnostic \
			"$script_dir/path_b_headless.exp" 5
		;;
	phase8)
		run_path path-a-gui pass blocking "$script_dir/path_a_gui.exp" 1
		run_path path-b-gui pass blocking "$script_dir/path_b_gui.exp" 2
		run_path path-a-headless non-gating-diagnostic diagnostic \
			"$script_dir/path_a_headless.exp" 4
		run_path path-b-headless non-gating-diagnostic diagnostic \
			"$script_dir/path_b_headless.exp" 3
		;;
esac
