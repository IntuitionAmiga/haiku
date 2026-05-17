# Encrypted Home Memory Hygiene

Passphrases are collected in userland and kept out of BMessages and argv.
Callers store them in secure buffers and cleanse those buffers when the
operation completes.

Argon2id derives 64 bytes. The first 32 bytes are the key-encryption key and
the second 32 bytes are the header MAC key. The derived buffer is cleansed on
all success and failure paths after HMAC verification and unwrap complete.

The master key crosses into the kernel once through
`IOCTL_ENCRYPTED_HOME_UNLOCK`. Userland cleanses its copy after the ioctl. The
kernel stores its copy in locked memory and zeroes it on lock, unregister, or
driver teardown.

Plaintext I/O buffers in the kernel driver are cleansed on error paths before
freeing. Partial user-copy failures cleanse any copied sensitive bytes before
returning.
