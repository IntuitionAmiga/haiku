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

run_qemu_placeholder()
{
	local run_name=$1
	local status=$2

	ehg_status "$status" "$run_name"
	ehg_die "$run_name requires the VNC/QEMU driver implementation; preflight passed but lifecycle automation is not complete"
}

run_preflight

if [ "${HAIKU_ENCRYPTED_HOME_PREFLIGHT_ONLY:-0}" = 1 ]; then
	ehg_status pass "$phase-preflight-only"
	exit 0
fi

[ -n "${HAIKU_ENCRYPTED_HOME_IMAGE:-}" ] \
	|| ehg_die "HAIKU_ENCRYPTED_HOME_IMAGE is required for full $phase gate"
[ -e "$HAIKU_ENCRYPTED_HOME_IMAGE" ] \
	|| ehg_die "image does not exist: $HAIKU_ENCRYPTED_HOME_IMAGE"

check_kvm

case "$phase" in
	phase7)
		run_qemu_placeholder path-a-gui pass
		run_qemu_placeholder path-b-install-only pass
		ehg_status non-gating-diagnostic path-a-headless
		ehg_status non-gating-diagnostic path-b-install-headless
		;;
	phase8)
		run_qemu_placeholder path-a-gui pass
		run_qemu_placeholder path-b-gui pass
		ehg_status non-gating-diagnostic path-a-headless
		ehg_status non-gating-diagnostic path-b-headless
		;;
esac
