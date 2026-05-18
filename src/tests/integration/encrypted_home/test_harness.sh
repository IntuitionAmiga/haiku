#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

tmp=${TMPDIR:-/tmp}/encrypted_home_gate_test.$$
trap 'rm -rf "$tmp"' EXIT INT TERM

make_root()
{
	local root=$1
	rm -rf "$root"
	mkdir -p \
		"$root/system/apps" \
		"$root/system/bin" \
			"$root/system/add-ons/kernel/drivers/bin" \
			"$root/system/add-ons/kernel/drivers/dev/disk/virtual" \
			"$root/system/add-ons/kernel/file_systems" \
			"$root/system/add-ons/disk_systems" \
			"$root/system/data/launch" \
			"$root/system/data/user_launch" \
			"$root/system/data/package_infos"

	printf 'Installer binary: Encrypt home folder; does not protect the system partition\n' \
		>"$root/system/apps/Installer"
	printf 'unlock synthetic\n' >"$root/system/apps/unlock_volume"
	printf 'cryptvol synthetic\n' >"$root/system/bin/cryptvol"
	printf 'driver synthetic\n' \
		>"$root/system/add-ons/kernel/drivers/bin/encrypted_home"
	ln -s ../../../bin/encrypted_home \
		"$root/system/add-ons/kernel/drivers/dev/disk/virtual/encrypted_home"
		printf 'kernel file system synthetic\n' \
			>"$root/system/add-ons/kernel/file_systems/encrypted_home"
		printf 'disk system synthetic\n' \
			>"$root/system/add-ons/disk_systems/encrypted_home"
	cat >"$root/system/data/launch/system" <<'EOF'
service x-vnd.Haiku-app_server {
	launch /system/servers/app_server
}
job x-vnd.Haiku-home_unlock {
	launch /system/apps/unlock_volume
	requires x-vnd.Haiku-app_server
	wait_for_exit
}
job x-vnd.Haiku-autologin-unlocked {
	requires x-vnd.Haiku-home_unlock
}
EOF
		cat >"$root/system/data/user_launch/user" <<'EOF'
service x-vnd.Haiku-app_server {
	if not file_exists /system/apps/unlock_volume
}
EOF
	printf 'requires\n\tlib:libcrypto\n' \
		>"$root/system/data/package_infos/haiku"
}

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

mkdir -p "$tmp"
root="$tmp/root"
make_root "$root"

assert_pass "$script_dir/image_contents.sh" --root "$root"

rm "$root/system/apps/unlock_volume"
assert_fail "$script_dir/image_contents.sh" --root "$root"
make_root "$root"

sed '/wait_for_exit/d' "$root/system/data/launch/system" \
	>"$root/system/data/launch/system.tmp"
mv "$root/system/data/launch/system.tmp" "$root/system/data/launch/system"
assert_fail "$script_dir/image_contents.sh" --root "$root"
make_root "$root"

	rm "$root/system/add-ons/disk_systems/encrypted_home"
	assert_fail "$script_dir/image_contents.sh" --root "$root"
	make_root "$root"

	mv "$root/system/data/user_launch/user" "$root/system/data/launch/user"
	assert_fail "$script_dir/image_contents.sh" --root "$root"
	make_root "$root"

	mkdir -p "$root/system/lib"
printf 'static library must not ship\n' \
	>"$root/system/lib/libencrypted_home_userland.a"
assert_fail "$script_dir/image_contents.sh" --root "$root"
make_root "$root"

export HAIKU_ENCRYPTED_HOME_IMAGE_ROOT="$root"
export HAIKU_ENCRYPTED_HOME_WORK_DIR="$tmp/work"
export HAIKU_ENCRYPTED_HOME_PREFLIGHT_ONLY=1
assert_pass "$script_dir/image_gate.sh" phase8

unset HAIKU_ENCRYPTED_HOME_PREFLIGHT_ONLY
export HAIKU_ENCRYPTED_HOME_IMAGE="$tmp/haiku-anyboot.iso"
export HAIKU_ENCRYPTED_HOME_SELF_TEST_DRY_RUN=1
export HAIKU_ENCRYPTED_HOME_SELF_TEST_ASSUME_KVM=1
printf 'synthetic image\n' >"$HAIKU_ENCRYPTED_HOME_IMAGE"
assert_pass "$script_dir/image_gate.sh" phase7
assert_pass grep -F "status: pass path-a-gui" "$tmp/work/phase7.log"
assert_pass grep -F "status: pass path-b-install-only" "$tmp/work/phase7.log"
assert_pass grep -F "status: non-gating-diagnostic path-a-headless" "$tmp/work/phase7.log"
assert_pass grep -F "status: non-gating-diagnostic path-b-install-headless" "$tmp/work/phase7.log"
assert_pass grep -F " -display vnc=:5 -serial file:$tmp/work/path-b-install-headless_serial.log # driver=$script_dir/path_b_headless.exp" "$tmp/work/phase7.log"
assert_pass "$script_dir/image_gate.sh" phase8
assert_pass grep -F "status: pass path-a-gui" "$tmp/work/phase8.log"
assert_pass grep -F "status: pass path-b-gui" "$tmp/work/phase8.log"
assert_pass grep -F "status: non-gating-diagnostic path-a-headless" "$tmp/work/phase8.log"
assert_pass grep -F "status: non-gating-diagnostic path-b-headless" "$tmp/work/phase8.log"

printf 'status: pass harness-self-test\n'
