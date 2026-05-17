# Encrypted Home Threat Model

## In Scope

Encrypted home protects against a stolen powered-off laptop. The attacker can
read the disk but does not know the passphrase and does not have live RAM
contents.

## Protected Data

The contents of `/boot/home` are confidential at rest. This includes user
files, attributes, and filesystem metadata inside the encrypted BFS volume. The
on-disk encrypted-home header remains visible and contains the volume UUID, KDF
parameters, and wrapped master key.

## Not Protected

Data-area tampering is not detected. AES-XTS provides confidentiality, not
authenticity, so an attacker who can modify ciphertext can cause corresponding
plaintext corruption after unlock.

Evil-maid attacks on the plaintext system partition are out of scope. The boot
path, kernel, app_server, and unlock application are not protected by v1.

Cold-boot RAM extraction is out of scope. Keys are present in locked kernel
memory while the volume is unlocked.

Running malware in the user's session is out of scope. After unlock, normal
processes can access plaintext home data according to the usual Haiku access
model.

Physical input capture, including hardware keyloggers and shoulder-surfing, is
out of scope.

Hibernation is out of scope. Haiku does not currently hibernate; any future
hibernation design must account for encrypted-home keys and plaintext memory.

Header rollback after passphrase change is out of scope. A passphrase change
rewraps the same master key, so an attacker who recorded an old header and
knows the old passphrase can restore that header. Post-compromise key rotation
requires backup, reformat, and restore.
