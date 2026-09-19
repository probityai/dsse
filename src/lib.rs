//! DSSE: the Dead Simple Signing Envelope, and the pre-authentication encoding
//! its signatures are computed over.
//!
//! DSSE is the envelope the in-toto and Sigstore families sign inside. This
//! crate implements the envelope and the encoding on their own, so a consumer
//! that needs neither of those stacks does not take either as a dependency.
//!
//! # What a signature covers
//!
//! A DSSE signature is not over the payload. It is over
//! `PAE(payload_type, payload)`, the pre-authentication encoding, which binds
//! the payload type inside the signed bytes:
//!
//! ```text
//! PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
//! ```
//!
//! That binding is the point. When the type is checked beside the signature
//! rather than inside it, a signature minted for one attestation type satisfies
//! a check for another. That was CVE-2022-35929 in cosign, scored 7.1 by
//! GitHub's advisory and 9.8 by NVD -- two scorers who disagree, not one agreed
//! number. Here the type is part of the pre-image, so the confusion has no
//! reachable path.
//!
//! # Verify, then read
//!
//! [`verify`] returns a [`VerifiedPayload`] holding the exact bytes the
//! signature covered. There is no second decode: the payload is decoded once,
//! that decode builds the pre-image, and those same bytes are what comes back.
//! The protocol requires this -- an implementation that re-parses the envelope
//! after verifying to pull the payload out can be made to hand the application
//! bytes nobody signed.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "ed25519")] {
//! use dsse::{sign, verify, Ed25519Signer};
//!
//! let signer = Ed25519Signer::from_bytes(&[7u8; 32])?.with_key_id("demo");
//! let verifier = signer.verifier();
//!
//! let envelope = sign("application/vnd.example+json", br#"{"a":1}"#, &signer)?;
//! let verified = verify(&envelope, &[&verifier], 1)?;
//!
//! assert_eq!(verified.payload, br#"{"a":1}"#);
//! assert_eq!(verified.payload_type, "application/vnd.example+json");
//! # }
//! # Ok::<(), dsse::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod envelope;
mod error;
mod pae;
mod sign;
mod traits;
mod verify;

#[cfg(feature = "ed25519")]
mod ed25519;

pub use envelope::{Envelope, Signature};
pub use error::{Error, Result};
pub use pae::pae;
pub use sign::{sign, sign_with};
pub use traits::{Signer, Verifier};
pub use verify::{verify, VerifiedPayload};

#[cfg(feature = "ed25519")]
pub use ed25519::{Ed25519Signer, Ed25519Verifier};
