# Encrypted Home Secret Boundary

The passphrase never crosses the kernel boundary. Userland components derive
keys, verify the header HMAC, and unwrap the master key.

```
passphrase
    |
    v
userland Argon2id -> KEK + MAC key
    |
    v
userland HMAC verify + AES unwrap -> master key
    |
    v
IOCTL_ENCRYPTED_HOME_UNLOCK -> kernel XTS context
```

The kernel driver receives only the cipher id, master-key length, and raw
master-key bytes. It does not parse encrypted-home headers, run Argon2id, or
receive the passphrase, KEK, or MAC key.
