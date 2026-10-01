# Security policy

CabinetPass is built so that nobody but you can read your vault. If you find
a way around that, I want to hear about it.

## Reporting a vulnerability

Email **govardhanchitrada@gmail.com** with the subject `SECURITY: CabinetPass`.
Please include:

- what you found and its impact;
- steps or a file to reproduce it (use the sample backup or a throwaway
  vault, never a real one);
- whether it affects this viewer, the file format, or the CabinetPass apps.

Please don't open a public issue for an unreleased vulnerability. You'll get
a reply within 72 hours. Once a fix ships, you'll be credited in the release
notes unless you'd rather not be.

## In scope

- Weaknesses in the file format or its use of Argon2id or AES-256-GCM
  ([decrypt/FORMAT.md](decrypt/FORMAT.md)).
- Anything that lets the Vault Viewer send data off the page, run injected
  script, or persist decrypted data.
- Differences between this implementation and the format specification.

## Not in scope

- Attacks that need an unlocked device, malware on the device, or the master
  password.
- Brute-forcing a weak master password. Argon2id slows guessing down, but it
  can't make a weak password strong.
