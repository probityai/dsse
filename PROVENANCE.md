# Provenance

What in this repository came from somewhere else, and at which commit.

## Specification text

The normative rules this crate implements are read from DSSE's own specification
text, not from a description of it. Each rule below names the file it is read from,
inside one pinned clone:

```text
github.com/secure-systems-lab/dsse
  commit    851704a287847d8dcaf7ae1ca76ce9169511ee88 (merge of PR #77, 2025-11-10)
  version   1.0.2, dated 2024-05-10
  clone     ~/Documents/git-clones/dsse

  protocol.md                     the PAE rule, the signature definition, the
                                  verification order, the multi-signature (t, n)
                                  rule, and the worked test vector
  envelope.md                     the JSON envelope shape and its parsing rules
  envelope.proto                  signatures is REQUIRED, with length at least 1
  implementation/signing_spec.py  the reference implementation, read for the base64
                                  fallback order and the doctest envelope.
                                  Apache-2.0, Google LLC

  quoted in                       src/pae.rs, tests/spec_vector.rs
```

Reading that reference implementation is also what backs the README's claim that it
allows four of the six things this crate refuses. Four readings, each in one function:

```text
PAE       takes len(payloadType) on a Python string, which counts characters
b64dec    accepts non-canonical trailing bits
Verify    appends one name per verifying entry, so a caller counting the result
          counts entries rather than keys
Verify    skips a verifier whose identifier does not match the envelope's
          unauthenticated hint
```

It does refuse an envelope whose signature list is empty, and it has no threshold
parameter to set to zero.

## Test vectors

```text
file    vectors/cross_lang_signing.json
bytes   73309
sha256  4ca7b6a63bcf512f6ba5314dc6a0fb6d20266c0a82f157972e240a99b4974531

copied verbatim from
        pkg/signing/crosslang/testdata/cross_lang_signing.json
        in a private Go codebase of ours
written at
        c55e3a3f3ab68573998d3e4724421163727fecf0 (2026-07-31)
that repository's HEAD when the file was copied
        4b716740e19096dc5824fcf066ab10601fe10642
```

Eleven fixtures, each with a payload type, the canonical signed body, the PAE
pre-image, and an ed25519 signature over it under one key. The `payload` member is
the pre-canonicalisation object and is not what any signature covers;
`canonical_b64` is.

## Ported logic

The PAE implementation follows one file of the same codebase: the same decimal
length, the same injectivity argument, and the same CVE-2022-35929 reasoning for
putting the payload type inside the signed bytes. A second implementation of the
same rule was read as a cross-check.

```text
pkg/signing/pae.go   at 99c1aa1502889dc9eaaa52c322202942022d1f71 (2026-08-11)
aee/pae.go           in github.com/probityai/agent-evidence-vectors, the cross-check
```

Four test ideas are ported from pkg/signing/pae_test.go: the specification vector,
the empty body, injectivity across the type and body boundary, and domain separation
between payload types. The multi-byte length-prefix cases, the base64 malleability
cases, the duplicate-signature threshold case and the key-hint denial cases are new
here; the Go suite has none of them.

## What the shipped vector file contains

The vector file is inside the packaged crate, so whatever it carries is published
with the crate. A publisher decides between two things before pushing a release:
regenerate the fixtures under neutral payload types, or publish the strings listed
here. Nothing yanks back once it is on a registry.

Counts are over the 73,309 bytes as they ship. A string can appear in the JSON text,
or only inside a base64 member, which must be decoded first: grepping the packaged
bytes finds the first kind and misses the second. The two columns are counted
separately for that reason, with DSSEv1 and aeeRunBinding as positive controls
proving each search path runs.

```text
string                                          in the JSON text   inside decoded bodies
application/vnd.probity.* payload types                       19                      11
aeeRunBinding and the AEE record field names                   0                      12
pkg/policy/idna.go                                             1                       4
pkg/policy/scrub.go                                            0                       3
NormalizeHost                                                  0                       4
```

Of those, aeeRunBinding and the AEE field names are public already, in 20 files of
github.com/probityai/agent-evidence-vectors. The five vendor media types and the
three Go identifiers are not public anywhere.

Three IP addresses appear, all inside decoded bodies:

```text
203.0.113.9    6 times   RFC 5737 documentation address, discloses nothing
203.0.113.10   3 times   RFC 5737 documentation address, discloses nothing
100.64.0.2     3 times   RFC 6598 shared address space, so a plausible internal
                         address rather than a reserved-for-documentation one
```

That last one reaches the file as a guest source address in a virtual-machine
introspection record, alongside a function name and a layer label from the same
codebase.

Regenerating costs one run of the Go generator under neutral payload types and a
throwaway key, and it keeps every property the suite relies on: real signatures over
real PAE pre-images from an independent implementation, and one payload that is not
UTF-8.

## Licences

secure-systems-lab/dsse is Apache-2.0, Google LLC and the DSSE maintainers, an
organisation rather than an individual. Contact is MAINTAINERS.md in that repository.
The vector file and the ported PAE logic are ours.

```text
base64, serde, serde_json, thiserror   MIT OR Apache-2.0
ed25519-dalek                          BSD-3-Clause, dalek-cryptography
```
