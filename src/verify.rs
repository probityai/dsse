//! Threshold verification, and the only type that carries verified bytes.

use crate::envelope::{decode_b64, Envelope};
use crate::error::{Error, Result};
use crate::pae::pae;
use crate::traits::Verifier;

/// A payload that a threshold of trusted keys has signed.
///
/// This is the only way this crate hands back payload bytes for an application
/// to act on. The bytes in [`VerifiedPayload::payload`] are the exact bytes the
/// signature covered: they are decoded once, that decode builds the
/// pre-authentication encoding, and those same bytes are moved into this struct.
/// The envelope is never read again afterwards, which is what the protocol's
/// re-parsing warning requires -- an implementation that goes back to the
/// envelope for the payload after verifying can be made to hand the application
/// bytes nobody signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayload {
    /// The authenticated payload type.
    pub payload_type: String,
    /// The exact bytes the signature covered.
    pub payload: Vec<u8>,
    /// The `key_id` of every distinct trusted key that verified, in the order
    /// the keys were supplied. A key reporting no identifier is named `#<n>` by
    /// its position.
    pub accepted_keys: Vec<String>,
}

/// Verifies an envelope against `keys`, requiring `threshold` distinct keys.
///
/// A `(t, n)` envelope is valid when signatures in it verify under at least `t`
/// of the `n` supplied keys. The count is over **distinct keys**, never over
/// signature entries: an envelope carrying one valid signature copied five times
/// has one key behind it, and counting entries would let a single key satisfy any
/// threshold. Each supplied key therefore contributes at most one, however many
/// entries it verifies.
///
/// The caller owns key distinctness. Passing the same key twice makes `n` wrong
/// and inflates the count, which is why [`Verifier::key_id`] is documented as
/// unique across a trusted set.
///
/// A decode failure anywhere in the envelope is a refusal, not a skipped
/// attempt: the protocol says to reject when decoding fails. A signature that
/// decodes but does not verify is skipped, as the protocol also says.
pub fn verify(
    envelope: &Envelope,
    keys: &[&dyn Verifier],
    threshold: usize,
) -> Result<VerifiedPayload> {
    if threshold == 0 {
        return Err(Error::ZeroThreshold);
    }
    if envelope.signatures.is_empty() {
        return Err(Error::NoSignatures);
    }

    let payload = decode_b64(&envelope.payload, "payload")?;
    let pre_image = pae(&envelope.payload_type, &payload);

    let mut entries = Vec::with_capacity(envelope.signatures.len());
    for entry in &envelope.signatures {
        let sig = decode_b64(&entry.sig, "signatures[].sig")?;
        entries.push((entry.keyid.as_deref().unwrap_or_default(), sig));
    }

    let mut accepted = Vec::new();
    for (idx, key) in keys.iter().enumerate() {
        let key_id = key.key_id();
        if key_accepts(*key, &pre_image, &entries, key_id.as_deref()) {
            accepted.push(key_id.unwrap_or_else(|| format!("#{idx}")));
        }
    }

    if accepted.len() < threshold {
        return Err(Error::ThresholdNotMet {
            accepted: accepted.len(),
            threshold,
        });
    }

    Ok(VerifiedPayload {
        payload_type: envelope.payload_type.clone(),
        payload,
        accepted_keys: accepted,
    })
}

/// Reports whether `key` verifies any of the envelope's signatures.
///
/// `keyid` is outside the pre-authentication encoding and so is attacker
/// controlled on any envelope an attacker can touch. The protocol allows it to
/// narrow the selection of keys to try and forbids using it for security
/// decisions, so it is used here only to try the matching entry first. Every
/// entry is still tried afterwards: a wrong or absent hint costs a few
/// signature checks and never withholds a verification that would otherwise
/// succeed.
fn key_accepts(
    key: &dyn Verifier,
    pre_image: &[u8],
    entries: &[(&str, Vec<u8>)],
    key_id: Option<&str>,
) -> bool {
    if let Some(id) = key_id.filter(|id| !id.is_empty()) {
        if entries
            .iter()
            .any(|(hint, sig)| *hint == id && key.verify(pre_image, sig))
        {
            return true;
        }
    }
    entries.iter().any(|(_, sig)| key.verify(pre_image, sig))
}
