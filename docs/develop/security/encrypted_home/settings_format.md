# Encrypted Home Settings Format

This file is generated from `headers/private/encrypted_home/settings_format.h`. Do not hand-edit the setting keys in this table.

Boot path: `/boot/system/settings/encrypted_home`.

Installer target-relative directory: `system/settings`.

File name: `encrypted_home`.

Installer target-relative path: `system/settings/encrypted_home`.

| Key | Required | Description |
| --- | --- | --- |
| `enabled` | yes | Boolean; true means unlock /boot/home at boot |
| `volume_uuid` | when enabled is true | Lowercase hexadecimal 128-bit encrypted-home volume UUID |

Example:

```text
enabled true
volume_uuid 00112233445566778899aabbccddeeff
```
