#![no_std]
#![forbid(unsafe_code)]

//! RFC 8018 PBKDF2 instantiated with the ABC HMAC-SHA-256 core.

use abc_hmac_sha256::{
    authenticate, HmacError, HmacSha256, MAX_INPUT_BYTES, MAX_KEY_BYTES, TAG_BYTES,
};
use core::{fmt, num::NonZeroU32};

const HMAC_KEY_BLOCK_BYTES: usize = 64;

/// Maximum length when the block index is encoded as a 32-bit integer.
pub const MAX_OUTPUT_BYTES: u64 = u32::MAX as u64 * TAG_BYTES as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    PasswordTooLong,
    SaltTooLong,
    OutputLength,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PasswordTooLong => "PBKDF2 password exceeds the HMAC key limit",
            Self::SaltTooLong => "PBKDF2 salt and block index exceed the HMAC input limit",
            Self::OutputLength => "PBKDF2 output length must be within 1..=MAX_OUTPUT_BYTES",
        })
    }
}

impl core::error::Error for Error {}

impl From<HmacError> for Error {
    fn from(error: HmacError) -> Self {
        match error {
            HmacError::KeyTooLong => Self::PasswordTooLong,
            HmacError::MessageTooLong => Self::SaltTooLong,
        }
    }
}

fn validate_lengths(password: u64, salt: u64, output: u64) -> Result<(), Error> {
    if password > MAX_KEY_BYTES {
        return Err(Error::PasswordTooLong);
    }
    if salt > MAX_INPUT_BYTES - 4 {
        return Err(Error::SaltTooLong);
    }
    if output == 0 || output > MAX_OUTPUT_BYTES {
        return Err(Error::OutputLength);
    }
    Ok(())
}

/// Derive a positive number of bytes using a nonzero iteration count.
/// Length validation is performed before any output byte is written.
pub fn derive(
    password: &[u8],
    salt: &[u8],
    iterations: NonZeroU32,
    output: &mut [u8],
) -> Result<(), Error> {
    validate_lengths(
        password.len() as u64,
        salt.len() as u64,
        output.len() as u64,
    )?;
    // HMAC normalizes long passwords to their SHA-256 digest before applying
    // the pads. Reuse that same key for every PRF call in the derivation.
    let hashed;
    let password = if password.len() > HMAC_KEY_BLOCK_BYTES {
        hashed = abc_sha256::digest(password).map_err(|_| Error::PasswordTooLong)?;
        &hashed[..]
    } else {
        password
    };
    for (index, target) in output.chunks_mut(TAG_BYTES).enumerate() {
        let block = derive_block(password, salt, iterations, index as u32 + 1)?;
        target.copy_from_slice(&block[..target.len()]);
    }
    Ok(())
}

fn derive_block(
    password: &[u8],
    salt: &[u8],
    iterations: NonZeroU32,
    index: u32,
) -> Result<[u8; TAG_BYTES], Error> {
    let mut mac = HmacSha256::new(password)?;
    mac.update(salt)?;
    mac.update(&index.to_be_bytes())?;
    let mut previous = mac.finalize()?;
    let mut block = previous;
    for _ in 1..iterations.get() {
        previous = authenticate(password, &previous)?;
        for (byte, term) in block.iter_mut().zip(previous) {
            *byte ^= term;
        }
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_validation_boundaries() {
        assert_eq!(
            validate_lengths(MAX_KEY_BYTES, MAX_INPUT_BYTES - 4, MAX_OUTPUT_BYTES),
            Ok(())
        );
        assert_eq!(
            validate_lengths(MAX_KEY_BYTES + 1, 0, 1),
            Err(Error::PasswordTooLong)
        );
        assert_eq!(
            validate_lengths(0, MAX_INPUT_BYTES - 3, 1),
            Err(Error::SaltTooLong)
        );
        assert_eq!(
            validate_lengths(0, 0, MAX_OUTPUT_BYTES + 1),
            Err(Error::OutputLength)
        );
    }
}
