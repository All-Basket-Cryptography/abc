#![no_std]
#![forbid(unsafe_code)]
//! Research implementation of HKDF with ABC HMAC-SHA-256.

use abc_hmac_sha256::{
    authenticate, HmacError, HmacSha256, MAX_INPUT_BYTES, MAX_KEY_BYTES, TAG_BYTES,
};
use core::fmt;

pub const PRK_BYTES: usize = TAG_BYTES;
pub const MAX_OUTPUT_BYTES: usize = u8::MAX as usize * TAG_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HkdfError {
    SaltTooLong,
    InputTooLong,
    PrkTooShort,
    PrkTooLong,
    InfoTooLong,
    OutputTooLong,
}

impl fmt::Display for HkdfError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::SaltTooLong => "HKDF salt exceeds the HMAC key length limit",
            Self::InputTooLong => {
                "HKDF input keying material exceeds the HMAC message length limit"
            }
            Self::PrkTooShort => "HKDF pseudorandom key must contain at least 32 bytes",
            Self::PrkTooLong => "HKDF pseudorandom key exceeds the HMAC key length limit",
            Self::InfoTooLong => "HKDF info exceeds the HMAC message length limit",
            Self::OutputTooLong => "HKDF output exceeds 8160 bytes",
        })
    }
}

impl core::error::Error for HkdfError {}

/// The 32-byte pseudorandom key returned by the extract step.
pub struct Prk([u8; PRK_BYTES]);

impl Prk {
    /// Borrow the caller-managed secret bytes for an explicit export.
    pub fn as_bytes(&self) -> &[u8; PRK_BYTES] {
        &self.0
    }

    /// Expand this key into a caller-owned output buffer.
    pub fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), HkdfError> {
        expand(&self.0, info, output)
    }
}

/// Extract a key from input keying material. An omitted salt uses 32 zero bytes.
pub fn extract(salt: Option<&[u8]>, input: &[u8]) -> Result<Prk, HkdfError> {
    let salt = salt.unwrap_or(&[0; PRK_BYTES]);
    authenticate(salt, input)
        .map(Prk)
        .map_err(|error| match error {
            HmacError::KeyTooLong => HkdfError::SaltTooLong,
            HmacError::MessageTooLong => HkdfError::InputTooLong,
        })
}

/// Expand a pseudorandom key of at least 32 bytes. Errors preserve the output buffer.
pub fn expand(prk: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), HkdfError> {
    if prk.len() < PRK_BYTES {
        return Err(HkdfError::PrkTooShort);
    }
    if u64::try_from(prk.len()).map_or(true, |length| length > MAX_KEY_BYTES) {
        return Err(HkdfError::PrkTooLong);
    }
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(HkdfError::OutputTooLong);
    }
    if output.is_empty() {
        return Ok(());
    }

    let overhead = if output.len() > TAG_BYTES {
        TAG_BYTES as u64 + 1
    } else {
        1
    };
    if u64::try_from(info.len()).map_or(true, |length| length > MAX_INPUT_BYTES - overhead) {
        return Err(HkdfError::InfoTooLong);
    }

    // All lengths are checked before writing any output.
    let mut previous = [0; TAG_BYTES];
    for (block, counter) in output.chunks_mut(TAG_BYTES).zip(1..=u8::MAX) {
        let mut hmac = HmacSha256::new(prk).map_err(|_| HkdfError::PrkTooLong)?;
        if counter > 1 {
            hmac.update(&previous).map_err(|_| HkdfError::InfoTooLong)?;
        }
        hmac.update(info).map_err(|_| HkdfError::InfoTooLong)?;
        hmac.update(&[counter])
            .map_err(|_| HkdfError::InfoTooLong)?;
        previous = hmac.finalize().map_err(|_| HkdfError::InfoTooLong)?;
        block.copy_from_slice(&previous[..block.len()]);
    }
    Ok(())
}

/// Extract and expand with one call into a caller-owned output buffer.
pub fn derive(
    salt: Option<&[u8]>,
    input: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), HkdfError> {
    extract(salt, input)?.expand(info, output)
}
