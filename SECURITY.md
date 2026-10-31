# Security

This repository contains **no API keys**.

- Keys are supplied at runtime from the encrypted credential store (`~/.zcode/v2/credentials.json`).
- The decryption key is derived from the local machine (username/home directory) or `ZCODE_CREDENTIAL_SECRET`.
- The script never prints or writes keys; error/evidence strings are redacted.
- Profile snapshots contain encrypted credentials and are gitignored.
- `backups/` contains credential file backups and is gitignored.

If a key is committed by accident: rotate it immediately, purge from history (or delete the repo), force-push.
