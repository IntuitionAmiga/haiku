# Encrypted Home Ioctl Format

This file is generated from `headers/private/encrypted_home/encrypted_home_driver_layout.h`. `encrypted_home_driver.h` asserts that the compiled ioctl structs match these constants. Do not hand-edit ioctl request layouts in this table.

All integer fields use the target ABI's normal representation. Userland and the kernel are built from the same private header.

## `encrypted_home_ioctl_register`

Size: 2072 bytes.

| Offset | Size | Field | Description |
| --- | ---: | --- | --- |
| 0x000 | 4 | `backingDevice` | Device id expected for the backing file or block device |
| 0x004 | 4 | `sectorSize` | Backing logical sector size; supported values are 512 and 4096 |
| 0x008 | 8 | `payloadSizeSectors` | Plaintext payload size in sectors |
| 0x010 | 1024 | `backingPath` | NUL-terminated path to the backing store |
| 0x410 | 4 | `id` | Returned encrypted-home device slot id |
| 0x414 | 1024 | `rawPath` | Returned raw virtual device path |

## `encrypted_home_ioctl_unregister`

Size: 4 bytes.

| Offset | Size | Field | Description |
| --- | ---: | --- | --- |
| 0x000 | 4 | `id` | Encrypted-home device slot id to unregister |

## `encrypted_home_ioctl_unlock`

Size: 72 bytes.

| Offset | Size | Field | Description |
| --- | ---: | --- | --- |
| 0x000 | 4 | `cipherId` | Cipher id from the authenticated encrypted-home header |
| 0x004 | 4 | `masterKeyLength` | Length of masterKey in bytes; 32 for AES-128-XTS, 64 for AES-256-XTS |
| 0x008 | 64 | `masterKey` | Unwrapped XTS master key bytes; unused tail must be zero |

## `encrypted_home_ioctl_info`

Size: 1048 bytes.

| Offset | Size | Field | Description |
| --- | ---: | --- | --- |
| 0x000 | 4 | `id` | Encrypted-home device slot id |
| 0x004 | 1 | `unlocked` | Whether the raw node currently has an active XTS key |
| 0x008 | 4 | `sectorSize` | Backing logical sector size |
| 0x010 | 8 | `payloadSizeSectors` | Plaintext payload size in sectors |
| 0x018 | 1024 | `backingPath` | Registered backing store path |
