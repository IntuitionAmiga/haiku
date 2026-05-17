# Encrypted Home Supported Architectures

The build-system source of truth is `ENCRYPTED_HOME_SUPPORTED_ARCHS` in `build/jam/encrypted_home_features.jam`.

| Architecture | Status |
| --- | --- |
| x86_64 | Supported when the OpenSSL build feature is enabled |
| riscv64 | Supported when the OpenSSL build feature is enabled |

Other packaging architectures skip encrypted-home targets in v1.
