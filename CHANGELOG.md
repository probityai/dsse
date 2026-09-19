# Changelog

A record of every notable change to this Rust crate. Its format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and its version numbers
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - unreleased

First release, so everything in it is new. Two decisions in it are worth reading
before you depend on it: the entry cap, and the one malformed input this crate
skips.

### Added

You can build a DSSE envelope, sign it with one key or with several, and verify it
against a threshold of keys you trust. The payload type goes inside the signed
bytes, where DSSE puts it, so a signature minted for one attestation type cannot
satisfy a check for another.

One trait signs and the other checks, so this crate holds no opinion about where a
key lives: an ECDSA key, a key in a KMS, or a Sigstore signer needs nothing from
the `ed25519` backend that ships on by default. Threshold verification counts
distinct keys, not signature entries, and it hands back the payload bytes the
signature covered. The envelope is never read again.

The suite ships DSSE's own test vector and 11 cross-language fixtures whose
signatures come from an independent implementation of the same encoding.

Verification refuses an envelope carrying more than 1024 signature entries, and it
refuses before doing any signature work. The cost of verifying is one check per
key per entry, and nothing inside an envelope bounds the entry count.

Eleven error variants say what went wrong. Nine are refusals: an empty payload
type, caught at signing and again at verification; an empty signature list; a
threshold of zero; a threshold above one that the supplied keys cannot be counted
apart under; base64 that is not canonical; more entries than the cap; a malformed
envelope; and a threshold the envelope does not meet. The remaining two pass a
backend failure through.

### Deliberately not refused

One entry that fails to decode does not fail the envelope. The signature list is
covered by no signature, so anyone who can touch an envelope can append to it, and
treating a single unusable entry as fatal would hand an attacker with no key a way
to deny verification of a validly signed envelope. Such an entry is skipped. An
envelope in which no entry at all decodes is still refused, and the refusal names
the member that failed, so the diagnostic survives.
