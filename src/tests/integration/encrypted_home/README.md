# Encrypted Home Image Gate

This directory contains host-side deployment gates for encrypted `/boot/home`.
The Jam targets run package/image preflight checks. The same scripts also
support full QEMU lifecycle runs when invoked directly with the required image,
work directory, QEMU, KVM, and Expect dependencies.

Jam targets:

- `EncryptedHomeImageGateSelfTest` validates the harness against synthetic image
  roots and does not require QEMU or KVM.
- `EncryptedHomeImageGate_Phase7` runs the Phase 7 image-content preflight.
- `EncryptedHomeImageGate_Phase8` runs the Phase 8/9 image-content preflight.

The phase targets require `HAIKU_ENCRYPTED_HOME_IMAGE_ROOT` to point at a
packagefs-resolved root directory. The Jam phase targets set
`HAIKU_ENCRYPTED_HOME_PREFLIGHT_ONLY=1`, so they do not start QEMU.
