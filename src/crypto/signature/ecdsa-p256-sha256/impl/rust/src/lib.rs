#![no_std]
#![forbid(unsafe_code)]
//! Fixed-format research profile for deterministic ECDSA P-256 with SHA-256.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

pub const PRIVATE_KEY_BYTES: usize = 32;
pub const COMPRESSED_PUBLIC_KEY_BYTES: usize = 33;
pub const UNCOMPRESSED_PUBLIC_KEY_BYTES: usize = 65;
pub const SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    VerificationFailed,
    SigningFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPrivateKey => "private scalar is outside 1..n",
            Self::InvalidPublicKey => "public key is not an admitted SEC 1 P-256 point",
            Self::InvalidSignature => "signature scalars are outside 1..n",
            Self::VerificationFailed => "ECDSA verification failed",
            Self::SigningFailed => "ECDSA signing failed",
        })
    }
}

impl core::error::Error for Error {}

/// Derive a 65-byte uncompressed SEC 1 public key from a big-endian private scalar.
pub fn public_key(
    private: &[u8; PRIVATE_KEY_BYTES],
) -> Result<[u8; UNCOMPRESSED_PUBLIC_KEY_BYTES], Error> {
    let key = SigningKey::from_slice(private).map_err(|_| Error::InvalidPrivateKey)?;
    let point = key.verifying_key().to_sec1_point(false);
    point
        .as_bytes()
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)
}

/// Sign a message with SHA-256 and the provider's deterministic RFC 6979 nonce.
/// The two big-endian scalars are returned without low-S normalization.
pub fn sign(
    private: &[u8; PRIVATE_KEY_BYTES],
    message: &[u8],
) -> Result<[u8; SIGNATURE_BYTES], Error> {
    let key = SigningKey::from_slice(private).map_err(|_| Error::InvalidPrivateKey)?;
    let signature: Signature = key.try_sign(message).map_err(|_| Error::SigningFailed)?;
    Ok(signature.to_bytes().into())
}

/// Verify a fixed-width signature using a compressed or uncompressed SEC 1 key.
pub fn verify(
    public: &[u8],
    message: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<(), Error> {
    match (public.first(), public.len()) {
        (Some(2 | 3), COMPRESSED_PUBLIC_KEY_BYTES) | (Some(4), UNCOMPRESSED_PUBLIC_KEY_BYTES) => {}
        _ => return Err(Error::InvalidPublicKey),
    }
    let key = VerifyingKey::from_sec1_bytes(public).map_err(|_| Error::InvalidPublicKey)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| Error::VerificationFailed)
}
