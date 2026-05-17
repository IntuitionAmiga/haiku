#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/lib.sh"

usage()
{
	cat <<'USAGE'
usage: image_contents.sh --root <packagefs-root>

The root must contain the packagefs-resolved deployed paths, for example
system/apps/Installer and system/data/launch/system.
USAGE
}

root=
while [ $# -gt 0 ]; do
	case "$1" in
		--root)
			[ $# -ge 2 ] || ehg_die "--root requires an argument"
			root=$2
			shift 2
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			ehg_die "unknown argument: $1"
			;;
	esac
done

[ -n "$root" ] || ehg_die "missing --root"
[ -d "$root" ] || ehg_die "root is not a directory: $root"

installer="$root/system/apps/Installer"
unlock="$root/system/apps/unlock_volume"
cryptvol="$root/system/bin/cryptvol"
driver="$root/system/add-ons/kernel/drivers/disk/virtual/encrypted_home"
kernel_file_system="$root/system/add-ons/kernel/file_systems/encrypted_home"
disk_system="$root/system/add-ons/disk_systems/encrypted_home"
launch_system="$root/system/data/launch/system"
launch_user="$root/system/data/user_launch/user"
package_info="$root/system/data/package_infos/haiku"

ehg_require_file "$installer"
ehg_require_file "$unlock"
ehg_require_file "$cryptvol"
ehg_require_file "$driver"
ehg_require_file "$kernel_file_system"
ehg_require_file "$disk_system"
ehg_require_file "$launch_system"
ehg_require_file "$launch_user"

ehg_require_strings_contains "$installer" "Encrypt home folder"
ehg_require_strings_contains "$installer" "does not protect the system partition"

ehg_require_contains "$launch_system" "service x-vnd.Haiku-app_server"
ehg_require_contains "$launch_system" "launch /system/servers/app_server"
ehg_require_contains "$launch_system" "job x-vnd.Haiku-home_unlock"
ehg_require_contains "$launch_system" "launch /system/apps/unlock_volume"
ehg_require_contains "$launch_system" "requires x-vnd.Haiku-app_server"
ehg_require_contains "$launch_system" "wait_for_exit"
ehg_require_contains "$launch_system" "requires x-vnd.Haiku-home_unlock"

ehg_require_contains "$launch_user" "if not file_exists /system/apps/unlock_volume"
ehg_require_absent "$root/system/lib/libencrypted_home_userland.a"
ehg_require_absent "$root/system/develop/lib/libencrypted_home_userland.a"

if [ -e "$package_info" ]; then
	ehg_require_contains "$package_info" "lib:libcrypto"
fi

if command -v readelf >/dev/null 2>&1 && file "$unlock" | grep -F ELF >/dev/null
then
	readelf -d "$unlock" | grep -E 'Shared library: \[libcrypto\.so' \
		>/dev/null || ehg_die "unlock_volume is not linked to libcrypto"
else
	ehg_note "readelf/ELF check skipped for synthetic or non-ELF root"
fi

ehg_status pass preflight-contents
