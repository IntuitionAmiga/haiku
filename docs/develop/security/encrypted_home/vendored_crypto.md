# Encrypted Home Vendored Crypto

AES-XTS support is vendored from OpenBSD softraid crypto code under
`src/libs/openbsd_softraid_crypto/`. The import keeps upstream source files
separate from the Haiku shim, and the `NOTICE` file records provenance.

Argon2id support is vendored from the P-H-C Argon2 reference implementation
under `src/libs/phc_argon2/`. The `NOTICE` file records provenance and license
information.

OpenSSL libcrypto is used as a platform dependency for AES key wrap,
HMAC-SHA256, constant-time comparison, random bytes, and memory cleansing.
OpenSSL is linked only into userland encrypted-home consumers, not libroot.
