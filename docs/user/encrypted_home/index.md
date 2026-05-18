# Encrypted Home Folder

Encrypted home protects the contents of `/boot/home` when the computer is
powered off and the disk is removed or read directly. During installation,
Installer formats a separate partition as the encrypted backing store, creates
a BFS filesystem inside it, and arranges for `/boot/home` to be mounted after
the passphrase is entered during boot.

Encrypted home is optional and requires a dedicated home partition. It is not a
single-partition full-disk-encryption mode. The system partition remains
plain BFS so Haiku can boot far enough to show the unlock window.

## Enabling It

In Installer, select the target system partition, enable "Encrypt home folder",
choose the prepared home backing partition, enter a passphrase, and choose the
cipher. Installer erases and formats the backing partition, then copies the home
tree into the encrypted volume during installation.

The passphrase is required to unlock the encrypted home volume. If it is
forgotten, the encrypted home contents cannot be recovered in v1. There is no
recovery key or second keyslot.

## What It Protects

Encrypted home protects user files, attributes, and BFS metadata stored under
`/boot/home` against offline reads of the powered-off disk by someone who does
not know the passphrase. The encrypted container header remains visible.

## What It Does Not Protect

The v1 feature does not protect against data-area tampering, attacks on the
plaintext system partition or boot path, cold-boot RAM extraction, malware
running in the unlocked session, physical input capture, hibernation, or header
rollback after passphrase change.
