# Provenance

What in this repository was taken from somewhere else, where from, and at which
commit.

## Specification text

The normative rules this crate implements are read from the specification's own
text, not from a description of it.

- `github.com/secure-systems-lab/dsse`, commit
  `851704a287847d8dcaf7ae1ca76ce9169511ee88` (merge of PR #77, 2025-11-10),
  cloned to `~/Documents/git-clones/dsse`. Spec version 1.0.2, dated 2024-05-10.
  - `protocol.md` — the PAE rule, the signature definition, the verification
    order, the multi-signature `(t, n)` rule, and the worked test vector.
  - `envelope.md` — the JSON envelope shape and its parsing rules.
  - `envelope.proto` — `signatures` REQUIRED with length >= 1.
  - `implementation/signing_spec.py` — the reference implementation, read for the
    base64 fallback order and the doctest envelope. Apache-2.0, Google LLC.

Quoted in `src/pae.rs` and `tests/spec_vector.rs`.

## Test vectors

`vectors/matchlock_cross_lang_signing.json`, 73,309 bytes,
sha256 `4ca7b6a63bcf512f6ba5314dc6a0fb6d20266c0a82f157972e240a99b4974531`.

Copied verbatim from `pkg/signing/crosslang/testdata/cross_lang_signing.json` in
a private Go implementation, last written at commit
`c55e3a3f3ab68573998d3e4724421163727fecf0` (2026-07-31); repository HEAD at the
time of copying was `4b716740e19096dc5824fcf066ab10601fe10642`.

Eleven fixtures, each with a payload type, the canonical signed body, the PAE
pre-image, and an ed25519 signature over it under one key. The `payload` member
is the pre-canonicalisation object and is not what any signature covers;
`canonical_b64` is.

## Ported logic

The PAE implementation follows `pkg/signing/pae.go` of the same repository, at
commit `99c1aa1502889dc9eaaa52c322202942022d1f71` (2026-08-11): the same
`strconv`-style decimal length, the same injectivity argument, and the same
CVE-2022-35929 reasoning for why the payload type belongs inside the signed
bytes. `aee/pae.go` of `github.com/probityai/agent-evidence-vectors` is a second
implementation of the same rule and was read as a cross-check.

Four test ideas are ported from `pkg/signing/pae_test.go`: the specification
vector, the empty body, injectivity across the type/body boundary, and
domain separation between payload types. The multi-byte length-prefix cases, the
base64 malleability cases, the duplicate-signature threshold case and the
`keyid` denial cases are new here; the Go suite has none of them.

## Before this crate is published

**The vector file carries strings that are not public today.** It ships inside
the packaged crate, so publishing discloses them. Checked against the public
`github.com/probityai/agent-evidence-vectors` working tree, with `DSSEv1`
(9 files) and `aeeRunBinding` (20 files) as positive controls proving the search
worked:

| String in the vector file | Already public | Note |
|---|---|---|
| `aeeRunBinding` and the AEE record field names | yes, 20 files | no new disclosure |
| `application/vnd.probity.*` payload types | no, 0 files | five internal vendor media types |
| `pkg/policy/idna.go`, `pkg/policy/scrub.go` | no, 0 files | internal source paths |
| `NormalizeHost` | no, 0 files | internal function name |

The IP addresses in the fixtures are in the `203.0.113.0/24` documentation range
and disclose nothing.

The remedy, if those strings should stay private, is to have the Go side emit an
equivalent fixture set under neutral payload types and a throwaway key. That
keeps every property the suite relies on — real signatures, real PAE pre-images,
an independent implementation, one non-UTF-8 payload — and costs one generator
run. It is not done here because publishing is not done here.

## Licences, as a line item

- `secure-systems-lab/dsse` — Apache-2.0, Google LLC and the DSSE maintainers.
  An organisation, not an individual. Contact is `MAINTAINERS.md` in that
  repository.
- `serde_json_canonicalizer`, `serde_jcs` — not dependencies of this crate;
  named only for context.
- Dependencies: `base64` (MIT OR Apache-2.0), `serde` and `serde_json`
  (MIT OR Apache-2.0), `thiserror` (MIT OR Apache-2.0), `ed25519-dalek`
  (BSD-3-Clause, dalek-cryptography).
- The vector file and the ported PAE logic are ours.
