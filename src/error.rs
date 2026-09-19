//! Typed refusals.

use thiserror::Error;

/// Every way this crate refuses an envelope, and nothing else.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Error {
    /// The envelope was not well-formed JSON, or a required member was absent.
    #[error("envelope is not a well-formed DSSE JSON envelope: {0}")]
    MalformedEnvelope(String),

    /// `payload` or a `sig` was not canonical RFC 4648 base64 in either the
    /// standard or the URL-safe alphabet.
    #[error("{field} is not canonical base64 in either the standard or URL-safe alphabet")]
    NonCanonicalBase64 {
        /// The envelope member that failed to decode.
        field: &'static str,
    },

    /// `signatures` was present but empty. The envelope schema requires at
    /// least one signature, so an empty list can never be satisfied.
    #[error("envelope carries no signatures; the schema requires at least one")]
    NoSignatures,

    /// Fewer than `threshold` distinct trusted keys produced a valid signature.
    #[error("signature threshold not met: {accepted} distinct trusted key(s) accepted, {threshold} required")]
    ThresholdNotMet {
        /// How many distinct trusted keys verified.
        accepted: usize,
        /// How many were required.
        threshold: usize,
    },

    /// A threshold of zero was requested. Zero would verify an envelope with no
    /// valid signature at all.
    #[error("a threshold of zero accepts an unsigned envelope")]
    ZeroThreshold,

    /// The signer could not produce a signature.
    #[error("signing failed: {0}")]
    Signing(String),

    /// A key could not be constructed from the supplied bytes.
    #[error("invalid key: {0}")]
    InvalidKey(String),
}

/// The result of any operation in this crate.
pub type Result<T> = core::result::Result<T, Error>;
