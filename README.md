# dsse

DSSE — the Dead Simple Signing Envelope — and the pre-authentication encoding its
signatures are computed over. In Rust, on its own, with no in-toto or Sigstore
dependency.

DSSE is the envelope the in-toto and Sigstore families sign inside. Until now
every Rust implementation of it shipped inside a product crate and carried that
product's name, so a consumer who needed the envelope took the product too. This
crate is the envelope and nothing else.

## What a signature covers

A DSSE signature is not over the payload. It is over `PAE(payload_type, payload)`:

```text
PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
LEN(s)          = ASCII decimal byte length of s, no leading zeros
```

The payload type is inside the signed bytes. That is the whole point of the
encoding: when a verifier checks the type beside the signature rather than inside
it, a signature minted for one attestation type satisfies a check for another.
That was CVE-2022-35929 in cosign, scored 7.1 by GitHub's advisory and 9.8 by
NVD — two scorers who disagree, not one agreed number.

## Verify, then read

```rust
use dsse::{sign, verify, Ed25519Signer};

let signer = Ed25519Signer::from_bytes(&seed)?.with_key_id("release-key");
let envelope = sign("application/vnd.in-toto+json", statement, &signer)?;

let verified = verify(&envelope, &[&signer.verifier()], 1)?;
// verified.payload is the exact bytes the signature covered.
```

`verify` returns the payload bytes. The envelope is decoded once, that decode
builds the pre-image, and those same bytes come back. There is no second read,
because an implementation that goes back to the envelope after verifying can be
made to hand the application bytes nobody signed — which the protocol says in
capitals and this API makes unreachable.

## Bring your own signatures

`ed25519` is a default feature, there so the crate works out of the box. Anything
else — ECDSA, a KMS, a Sigstore signer — implements two traits and needs nothing
from it:

```toml
dsse = { version = "0.1", default-features = false }
```

```rust
impl dsse::Verifier for MyKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool { /* ... */ }
    fn key_id(&self) -> Option<String> { Some(self.id.clone()) }
}
```

## What it refuses

Six refusals, each one a test that fails against an implementation without it.
Four of the six are places the specification's own reference implementation is
permissive.

| Refusal | Why |
|---|---|
| A length prefix counting characters | `LEN` is the byte length. For a non-ASCII payload type the two differ, and the signatures do not interoperate. |
| Base64 with non-zero trailing bits, or unpadded | `eA==` and `eB==` both decode to `x` under a lenient decoder. One signature over two envelope spellings is malleability. |
| An envelope with no signatures | The schema requires at least one. An empty list can meet no threshold. |
| A threshold of zero | It would accept an envelope no trusted key signed. |
| A threshold met by counting signature entries | The protocol counts **unique keys**. One valid signature copied five times is one key, so each key contributes at most once. |
| A `keyid` treated as a filter | `keyid` is outside the signed bytes and so attacker-controlled. Here it orders attempts and never excludes a key, so a wrong hint cannot withhold a valid verification. |

## Tests

46 tests. Two suites load pinned vectors and four construct attacks:

- **pinned** — the vector printed in the DSSE specification's own `protocol.md`,
  and 11 cross-language fixtures carrying real ed25519 signatures over PAE
  pre-images produced by an independent Go implementation. One fixture's payload
  is raw binary rather than JSON.
- **invented** — the length prefix under multi-byte and astral payload types,
  empty payloads and empty types, a payload that is itself a valid PAE, base64
  malleability in both members, the duplicate-signature threshold bypass, and
  the `keyid` denial.

Every pinned vector passes against an implementation carrying all six defects.
That is what the invented suites are for.

## License

Apache-2.0.
