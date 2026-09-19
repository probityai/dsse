# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - unreleased

First release. DSSE envelopes with PAE pre-authentication encoding:
construction, signing, and threshold verification.

### Added

- `Envelope`, `Signature`, and the PAE pre-image builder, with the payload type
  inside the signed bytes where DSSE puts it.
- `sign` and `sign_with`, and `verify` with an n-of-m threshold.
- `Signer` and `Verifier` traits, so the crate carries no opinion about where a
  key lives; an `ed25519` feature, on by default, wires `ed25519-dalek`.
- The specification's own test vector, plus cross-language fixtures.
- `MAX_SIGNATURES` (1024), refused as `Error::TooManySignatures` before any
  signature work: verification cost is keys times entries and nothing in an
  envelope bounds entries.

### Refusals

- An empty payload type, at signing and independently at verification. A crate
  whose argument is that the type is inside the signed bytes must not mint an
  envelope binding no type.
- A threshold above one where any supplied key reports no key id, or two report
  the same one. The count is over distinct keys; a set that cannot be counted is
  refused rather than counted wrongly.

### Deliberately not refused

- A signature entry that does not decode. The `signatures` array is covered by
  no signature, so appending an entry costs an attacker with no key nothing;
  treating one unusable entry as fatal would let them deny verification of a
  validly signed envelope. An entry that does not decode is skipped, and an
  envelope in which no entry decodes is still refused by field so the diagnostic
  is kept.
