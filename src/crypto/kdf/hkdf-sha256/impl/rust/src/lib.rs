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
        expand_from_prk(self, info, output)
    }
}

fn expand_from_prk(prk: &Prk, info: &[u8], output: &mut [u8]) -> Result<(), HkdfError> {
    expand(&prk.0, info, output)
}

/// Extract a key from input keying material. An omitted salt uses 32 zero bytes.
pub fn extract(salt: Option<&[u8]>, input: &[u8]) -> Result<Prk, HkdfError> {
    let tag = match salt {
        Some(salt) => authenticate(salt, input),
        None => authenticate(&[0; PRK_BYTES], input),
    };
    match tag {
        Ok(tag) => Ok(Prk(tag)),
        Err(HmacError::KeyTooLong) => Err(HkdfError::SaltTooLong),
        Err(HmacError::MessageTooLong) => Err(HkdfError::InputTooLong),
    }
}

/// Expand a pseudorandom key of at least 32 bytes. Errors preserve the output buffer.
pub fn expand(prk: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), HkdfError> {
    validate_expansion(prk.len(), info.len(), output.len())?;

    let mut previous = [0; TAG_BYTES];
    let mut offset = 0;
    let mut counter = 1usize;
    while offset < output.len() {
        previous = expand_block(prk, &previous, info, counter as u8)?;
        offset = copy_block(output, offset, &previous);
        counter += 1;
    }
    Ok(())
}

fn validate_expansion(prk_len: usize, info_len: usize, output_len: usize) -> Result<(), HkdfError> {
    if prk_len < PRK_BYTES {
        return Err(HkdfError::PrkTooShort);
    }
    let key_bytes = prk_len as u64;
    if key_bytes as usize != prk_len || key_bytes > MAX_KEY_BYTES {
        return Err(HkdfError::PrkTooLong);
    }
    if output_len > MAX_OUTPUT_BYTES {
        return Err(HkdfError::OutputTooLong);
    }
    if output_len == 0 {
        return Ok(());
    }

    let overhead = if output_len > TAG_BYTES {
        TAG_BYTES as u64 + 1
    } else {
        1
    };
    let info_bytes = info_len as u64;
    if info_bytes as usize != info_len || info_bytes > MAX_INPUT_BYTES - overhead {
        return Err(HkdfError::InfoTooLong);
    }
    Ok(())
}

fn expand_block(
    prk: &[u8],
    previous: &[u8; TAG_BYTES],
    info: &[u8],
    counter: u8,
) -> Result<[u8; TAG_BYTES], HkdfError> {
    let mut hmac = match HmacSha256::new(prk) {
        Ok(hmac) => hmac,
        Err(_) => return Err(HkdfError::PrkTooLong),
    };
    if counter > 1 {
        let Ok(()) = hmac.update(previous) else {
            return Err(HkdfError::InfoTooLong);
        };
    }
    let Ok(()) = hmac.update(info) else {
        return Err(HkdfError::InfoTooLong);
    };
    let Ok(()) = hmac.update(&[counter]) else {
        return Err(HkdfError::InfoTooLong);
    };
    match hmac.finalize() {
        Ok(tag) => Ok(tag),
        Err(_) => Err(HkdfError::InfoTooLong),
    }
}

fn copy_block(output: &mut [u8], mut offset: usize, block: &[u8; TAG_BYTES]) -> usize {
    let mut i = 0;
    while i < TAG_BYTES && offset < output.len() {
        output[offset] = block[i];
        i += 1;
        offset += 1;
    }
    offset
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
