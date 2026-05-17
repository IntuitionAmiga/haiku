# Encrypted Home Folder

Encrypted home protects the contents of `/boot/home` when the computer is
powered off and the disk is removed or read directly. During installation,
Installer can format a separate partition as an encrypted backing store, create
a BFS filesystem inside it, and arrange for `/boot/home` to be mounted only
after the passphrase is entered at boot.

Encrypted home is optional and requires a dedicated home partition. It is not a
single-partition full-disk-encryption mode. The system partition remains
plain BFS so Haiku can boot far enough to show the unlock window.

## Enabling It

In Installer, select the target system partition, enable "Encrypt home folder",
choose the prepared home backing partition, enter a passphrase, and choose the
cipher. Installer formats the backing partition and copies the home tree into
the encrypted volume during installation.

The passphrase is required on every encrypted-home boot. If it is forgotten,
the encrypted home contents are unrecoverable in v1. There is no recovery key
or second keyslot.

## What It Protects

Encrypted home protects user files, attributes, and BFS metadata stored under
`/boot/home` against offline reads of the powered-off disk by someone who does
not know the passphrase.

## What It Does Not Protect

The v1 feature does not protect against data-area tampering, evil-maid attacks
on the plaintext system partition, cold-boot RAM extraction, malware running in
the unlocked session, physical input capture, hibernation issues if hibernation
is added later, or header rollback after passphrase change.

Backups of `/boot/home` are plaintext unless the backup tool or destination
encrypts them separately. External tools that inspect the backing partition
directly see only the encrypted container header and ciphertext.
