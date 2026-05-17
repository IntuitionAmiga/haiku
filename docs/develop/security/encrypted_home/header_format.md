# Encrypted Home Header Format

This file is generated from `headers/private/encrypted_home/header_layout.h`. Do not hand-edit the byte offsets in this table.

All integer fields are little-endian. The header is 4096 bytes. The header HMAC covers bytes [0x000, 0x0c0).

| Offset | Size | Field | Description |
| --- | ---: | --- | --- |
| 0x000 | 8 | `magic` | "HAIKUENC" |
| 0x008 | 2 | `version` | Format version; currently 1 |
| 0x00a | 2 | `flags` | Reserved for v1; must be zero |
| 0x00c | 4 | `sector_size` | 512 or 4096 |
| 0x010 | 8 | `payload_offset_sectors` | First plaintext payload sector; always 16 |
| 0x018 | 8 | `payload_size_sectors` | Plaintext payload size in sectors |
| 0x020 | 4 | `cipher_id` | 1 = AES-128-XTS, 2 = AES-256-XTS |
| 0x024 | 4 | `kdf_id` | 1 = Argon2id |
| 0x028 | 4 | `argon2_t_cost` | Argon2id time cost |
| 0x02c | 4 | `argon2_m_cost` | Argon2id memory cost in KiB |
| 0x030 | 4 | `argon2_parallelism` | Argon2id lane count |
| 0x034 | 12 | `reserved` | Must be zero |
| 0x040 | 16 | `volume_uuid` | Random volume UUID |
| 0x050 | 32 | `kdf_salt` | Argon2id salt |
| 0x070 | 72 | `wrapped_master_key` | AES key-wrap output; AES-128-XTS tail must be zero |
| 0x0b8 | 4 | `sequence_number` | Monotonic header generation; zero is invalid |
| 0x0bc | 4 | `reserved` | Must be zero |
| 0x0c0 | 32 | `header_hmac_sha256` | HMAC-SHA256 over bytes [0x000, 0x0c0) |
| 0x0e0 | 3872 | `padding` | Must be zero |

Primary header sector: 0. Backup header sector: 8. Payload starts at sector 16.
