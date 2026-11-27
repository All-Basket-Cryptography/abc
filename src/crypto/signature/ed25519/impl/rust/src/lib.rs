#![no_std]
#![forbid(unsafe_code)]

//! Raw RFC 8032 Ed25519 over the pinned native Dalek implementation.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub const SEED_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    InvalidPublicKey,
    InvalidSignature,
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPublicKey => "Ed25519 public key decoding failed",
            Self::InvalidSignature => "Ed25519 strict verification failed",
        })
    }
}

impl core::error::Error for VerificationError {}

/// Derive the raw public key from a 32-byte Ed25519 seed.
pub fn public_key(seed: &[u8; SEED_BYTES]) -> [u8; PUBLIC_KEY_BYTES] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign the exact message bytes in pure Ed25519 mode with the supplied seed.
pub fn sign(seed: &[u8; SEED_BYTES], message: &[u8]) -> [u8; SIGNATURE_BYTES] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Verify with Dalek's strict policy over raw public-key and signature bytes.
pub fn verify_strict(
    public_key: &[u8; PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<(), VerificationError> {
    let key =
        VerifyingKey::from_bytes(public_key).map_err(|_| VerificationError::InvalidPublicKey)?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| VerificationError::InvalidSignature)
}
