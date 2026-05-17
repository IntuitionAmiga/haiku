# Encrypted Home Algorithms

Encrypted home uses established primitives and keeps passphrase handling in
userland.

| Purpose | Algorithm |
| --- | --- |
| Data confidentiality | AES-XTS, AES-128-XTS or AES-256-XTS |
| Passphrase KDF | Argon2id |
| Master-key wrapping | AES key wrap from RFC 3394 |
| Header authentication | HMAC-SHA256 |
| Random generation | OpenSSL `RAND_bytes` |

Default Argon2id parameters are time cost 3, memory cost 65536 KiB, and
parallelism 4. Headers may carry other bounded parameters accepted by the
parser.

AES-XTS is used according to the storage-confidentiality role described by
NIST SP 800-38E and IEEE 1619. It does not authenticate data sectors.
Argon2id follows RFC 9106 guidance for password hashing. AES key wrap follows
RFC 3394.
