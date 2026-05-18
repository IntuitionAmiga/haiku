# Encrypted Home

Encrypted home protects `/boot/home` at rest when the machine is powered off.
It does not protect the system partition.

## Threat Model

In scope: an attacker can read the powered-off disk but does not know the
passphrase and does not have live RAM contents.

Protected: user files, attributes, and filesystem metadata inside the encrypted
BFS home volume. The encrypted-home header remains visible and contains the
volume UUID, KDF parameters, and wrapped master key.

Out of scope:

- Data-area tampering
- Attacks on the plaintext system partition and boot path
- Cold-boot RAM extraction
- Running malware in the user's session
- Physical input capture
- Hibernation
- Header rollback after passphrase change

AES-XTS provides confidentiality, not authenticity. A passphrase change rewraps
the same master key; it does not rotate the data-encryption key.

## Algorithms

| Purpose | Algorithm |
| --- | --- |
| Data confidentiality | AES-128-XTS or AES-256-XTS |
| Passphrase KDF | Argon2id |
| Master-key wrapping | AES key wrap from RFC 3394 |
| Header authentication | HMAC-SHA256 |
| Random generation | OpenSSL `RAND_bytes` |

Default Argon2id parameters are time cost 3, memory cost 65536 KiB, and
parallelism 4. Parsed headers may carry bounded parameters: time cost 1 to 10,
memory cost 1 to 65536 KiB, parallelism 1 to 16, with memory cost at least
eight times the parallelism.

## Secret Boundary

Passphrase handling is in userland. Userland derives the key-encryption key and
MAC key, verifies the header HMAC, unwraps the master key, and passes only the
unwrapped master key to the kernel with `IOCTL_ENCRYPTED_HOME_UNLOCK`.

The kernel driver does not parse encrypted-home headers, run Argon2id, or
receive the passphrase, key-encryption key, or MAC key.
