# Encrypted Home Wire IDs

This file is generated from private encrypted-home headers. Do not hand-edit the numeric IDs in these tables.

## Cipher IDs

| Name | Value | Hex | Description |
| --- | ---: | ---: | --- |
| `kCipherAES128XTS` | 1 | 0x1 | AES-128-XTS with a 32-byte master key |
| `kCipherAES256XTS` | 2 | 0x2 | AES-256-XTS with a 64-byte master key |

## KDF IDs

| Name | Value | Hex | Description |
| --- | ---: | ---: | --- |
| `kKdfArgon2id` | 1 | 0x1 | Argon2id password KDF |

## Ioctl IDs

| Name | Value | Hex | Description |
| --- | ---: | ---: | --- |
| `IOCTL_ENCRYPTED_HOME_REGISTER` | 11999 | 0x2edf | Register a backing store and publish a raw virtual device |
| `IOCTL_ENCRYPTED_HOME_UNREGISTER` | 12000 | 0x2ee0 | Unpublish a registered encrypted-home virtual device |
| `IOCTL_ENCRYPTED_HOME_UNLOCK` | 12001 | 0x2ee1 | Install an unwrapped master key into the raw virtual device |
| `IOCTL_ENCRYPTED_HOME_LOCK` | 12002 | 0x2ee2 | Drop the active XTS key from the raw virtual device |
| `IOCTL_ENCRYPTED_HOME_INFO` | 12003 | 0x2ee3 | Return current registration and unlock state |
