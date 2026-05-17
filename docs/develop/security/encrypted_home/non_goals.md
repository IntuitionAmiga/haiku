# Encrypted Home Non-Goals

The v1 encrypted-home feature does not protect against:

- Data-area tampering
- Evil-maid attacks on the plaintext system partition
- Cold-boot RAM extraction
- Running malware in the user's session
- Physical input capture
- Hibernation
- Header rollback after passphrase change

These limitations are part of the v1 threat model and must remain visible in
user-facing and developer documentation.
