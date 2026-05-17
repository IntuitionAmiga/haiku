# Encrypted Home Image Gate

This directory contains the host-side deployment gate for encrypted `/boot/home`.
It currently validates package/image contents before the QEMU lifecycle runs.

Jam targets:

- `EncryptedHomeImageGateSelfTest` validates the harness against synthetic image
  roots and does not require QEMU or KVM.
- `EncryptedHomeImageGate_Phase7` runs the Phase 7 image-content preflight.
- `EncryptedHomeImageGate_Phase8` runs the Phase 8/9 image-content preflight.

The phase targets require `HAIKU_ENCRYPTED_HOME_IMAGE_ROOT` to point at a
packagefs-resolved root directory. Full QEMU lifecycle automation is kept out of
these gating targets until the driver implementation is complete.
