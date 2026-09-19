//! PINNED VECTORS. All 11 cases are loaded from
//! `vectors/matchlock_cross_lang_signing.json`, copied verbatim from
//! `pkg/signing/crosslang/testdata/cross_lang_signing.json` in a private Go
//! implementation at commit c55e3a3f3ab68573998d3e4724421163727fecf0
//! (2026-07-31). Each case carries a payload type, the PAE bytes that
//! implementation produced, and a real ed25519 signature over them, so the two
//! implementations agree byte for byte or a case fails. Nothing here is
//! invented.
//!
//! `canonical_b64` is the signed body: the RFC 8785 canonical bytes the Go
//! implementation put through PAE. The fixture's `payload` member is the
//! pre-canonicalisation object and is not what any signature covers.

#![cfg(feature = "ed25519")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use dsse::{pae, Ed25519Verifier, Envelope, Signature, Verifier};

const VECTORS: &str = include_str!("../vectors/matchlock_cross_lang_signing.json");

fn b64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// The 32 raw bytes of the fixture's ed25519 public key, taken from the tail of
/// its SPKI DER. The 12-byte prefix `302a300506032b6570032100` is the fixed
/// ed25519 SubjectPublicKeyInfo header.
fn fixture_key(v: &serde_json::Value) -> Ed25519Verifier {
    let pem = v["public_key_pem"].as_str().unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = b64(&body);
    assert_eq!(der.len(), 44, "SPKI DER for ed25519 is 44 bytes");
    let raw = &der[12..];
    let key_id = v["key_id"].as_str().unwrap().to_string();
    Ed25519Verifier::from_bytes(raw)
        .unwrap()
        .with_key_id(key_id)
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

/// Our PAE must reproduce, byte for byte, the pre-image the Go implementation
/// signed. Eleven cases across five payload types, including one whose payload
/// is raw binary rather than JSON.
#[test]
fn pae_matches_the_go_implementation_byte_for_byte() {
    let v = vectors();
    let fixtures = v["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 11, "the fixture file carries 11 cases");

    for f in fixtures {
        let name = f["name"].as_str().unwrap();
        let payload_type = f["payload_type"].as_str().unwrap();
        let want_pae = b64(f["pae_b64"].as_str().unwrap());
        let payload = b64(f["canonical_b64"].as_str().unwrap());

        let got = pae(payload_type, &payload);
        assert_eq!(
            got,
            want_pae,
            "PAE mismatch for {name}\n got {:?}\nwant {:?}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&want_pae)
        );
    }
}

/// Every fixture signature must verify against the PAE we reconstruct. This is
/// the byte-identity claim with the cryptography attached: if our PAE differed
/// from theirs by one byte, no signature would verify.
#[test]
fn every_fixture_signature_verifies_against_our_reconstruction() {
    let v = vectors();
    let key = fixture_key(&v);
    let mut checked = 0usize;

    for f in v["fixtures"].as_array().unwrap() {
        let name = f["name"].as_str().unwrap();
        let payload_type = f["payload_type"].as_str().unwrap();
        let payload = b64(f["canonical_b64"].as_str().unwrap());
        let sig = b64(f["signature_b64"].as_str().unwrap());
        assert_eq!(sig.len(), 64, "{name}: ed25519 signatures are 64 bytes");

        let pre_image = pae(payload_type, &payload);
        assert!(
            key.verify(&pre_image, &sig),
            "{name}: fixture signature did not verify against our PAE"
        );
        checked += 1;
    }
    assert_eq!(checked, 11);
}

/// One fixture's payload is raw binary: a big-endian u64 count followed by a
/// 32-byte Merkle root, so it contains NUL bytes and is not valid UTF-8. The
/// payload must survive base64 and PAE verbatim.
#[test]
fn binary_payload_survives_the_round_trip() {
    let v = vectors();
    let key = fixture_key(&v);
    let f = v["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "catch_batch_root")
        .expect("the binary-payload fixture must be present");

    let payload = b64(f["canonical_b64"].as_str().unwrap());
    assert_eq!(payload.len(), 40, "u64 count plus a 32-byte root");
    assert!(
        payload.starts_with(&[0, 0, 0, 0, 0, 0, 0, 8]),
        "count is 8 BE"
    );
    assert!(
        String::from_utf8(payload.clone()).is_err(),
        "this payload is deliberately not valid UTF-8"
    );

    let payload_type = f["payload_type"].as_str().unwrap();
    let sig = b64(f["signature_b64"].as_str().unwrap());
    assert!(key.verify(&pae(payload_type, &payload), &sig));
}

/// A whole envelope built from a fixture must verify end to end through the
/// public API, not only through `pae` directly.
#[test]
fn fixture_verifies_through_the_public_envelope_api() {
    let v = vectors();
    let key = fixture_key(&v);
    let f = &v["fixtures"].as_array().unwrap()[0];

    let env = Envelope {
        payload: f["canonical_b64"].as_str().unwrap().to_string(),
        payload_type: f["payload_type"].as_str().unwrap().to_string(),
        signatures: vec![Signature {
            keyid: Some(v["key_id"].as_str().unwrap().to_string()),
            sig: f["signature_b64"].as_str().unwrap().to_string(),
        }],
    };

    let verified = dsse::verify(&env, &[&key], 1).expect("fixture envelope must verify");
    assert_eq!(verified.payload, b64(f["canonical_b64"].as_str().unwrap()));
    assert_eq!(verified.payload_type, f["payload_type"].as_str().unwrap());
    assert_eq!(verified.accepted_keys.len(), 1);
}

/// A signature minted for one payload type must not verify under another. The
/// fixtures give two real types signed by the same key, so the cross-type
/// attempt uses genuine material rather than a constructed one.
#[test]
fn fixture_signature_does_not_verify_under_another_payload_type() {
    let v = vectors();
    let key = fixture_key(&v);
    let fixtures = v["fixtures"].as_array().unwrap();

    let record = fixtures
        .iter()
        .find(|f| f["name"] == "catch_record_0")
        .unwrap();
    let other = fixtures
        .iter()
        .find(|f| f["name"] == "freeze_binding_full")
        .unwrap();

    let payload = b64(record["canonical_b64"].as_str().unwrap());
    let sig = b64(record["signature_b64"].as_str().unwrap());
    let wrong_type = other["payload_type"].as_str().unwrap();

    assert!(
        !key.verify(&pae(wrong_type, &payload), &sig),
        "a signature must not verify once the payload type is swapped"
    );
}
