# Qubes GPG Sign

Qubes GPG Sign is a [Qubes OS](https://www.qubes-os.org) service that lets one
qube sign data with GnuPG keys held in another, more trusted qube. The data to
sign is passed over qrexec to the qube that holds the keys, so the keys never
leave it — they can stay in a network-isolated qube — and only the signature
comes back.

The caller passes the 40-character fingerprint of the key it wants to use as the
qrexec service argument, so a qrexec policy in dom0 can control which qubes may
sign with which keys. Compared to [Split GPG](https://www.qubes-os.org/doc/split-gpg/),
this service aims for simplicity and a minimal attack surface.

The qube that holds the keys installs the `qubes-gpg-sign` package, which
provides three qrexec services:

- `qubes.GpgBinarySign` — binary (detached) OpenPGP signature
- `qubes.GpgArmorSign` — ASCII-armored detached OpenPGP signature
- `qubes.GpgClearSign` — cleartext OpenPGP signature

Each service reads the data to sign on stdin and writes the signature to stdout.
