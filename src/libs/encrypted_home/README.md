# Encrypted Home Private Library

`libencrypted_home_userland.a` is a private static library for encrypted-home
userland consumers: Installer, `cryptvol`, `unlock_volume`, and tests. It is
not public API and is not packaged as a shared library.

The library owns the v1 on-disk header codec, Argon2id key derivation,
AES key-wrap handling, HMAC verification, and the userland block translator.
Kernel code receives only an unwrapped master key through the encrypted-home
ioctl interface and does not link this library.

The header wire layout is defined in
`headers/private/encrypted_home/header_layout.h`. Documentation in
`docs/develop/security/encrypted_home/header_format.md` is generated from that
header by `src/tools/encrypted_home_docs_gen`; byte offsets should not be
duplicated by hand in new docs.
