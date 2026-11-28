#![no_std]
#![forbid(unsafe_code)]
//! SP 800-38D fixed profile over the native RustCrypto provider.

use aes_gcm::{
    aead::{AeadInOut, KeyInit},
    Aes256Gcm,
};

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;
pub const MAX_MESSAGE_BYTES: u64 = (u32::MAX as u64 - 1) * 16;
pub const MAX_AAD_BYTES: u64 = u64::MAX / 8;

const _: () = {
    assert!(MAX_MESSAGE_BYTES == aes_gcm::P_MAX);
    assert!(MAX_AAD_BYTES == aes_gcm::A_MAX);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    MessageTooLong,
    AssociatedDataTooLong,
    AuthenticationFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::MessageTooLong => "GCM payload exceeds the counter domain",
            Self::AssociatedDataTooLong => "GCM associated data exceeds the bit-length domain",
            Self::AuthenticationFailed => "GCM tag verification failed",
        })
    }
}

impl core::error::Error for Error {}

/// Seal the data in place with a detached full-length tag.
/// Use a unique nonce for each encryption under the key.
pub fn seal_in_place(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; TAG_BYTES], Error> {
    check_lengths(aad.len() as u64, data.len() as u64)?;
    Aes256Gcm::new(key.into())
        .encrypt_inout_detached(nonce.into(), aad, data.into())
        .map(Into::into)
        .map_err(|_| Error::MessageTooLong)
}

/// Open the data in place and preserve the input on rejection.
pub fn open_in_place(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_BYTES],
) -> Result<(), Error> {
    check_lengths(aad.len() as u64, data.len() as u64)?;
    Aes256Gcm::new(key.into())
        .decrypt_inout_detached(nonce.into(), aad, data.into(), tag.into())
        .map_err(|_| Error::AuthenticationFailed)
}

fn check_lengths(aad: u64, data: u64) -> Result<(), Error> {
    if data > MAX_MESSAGE_BYTES {
        return Err(Error::MessageTooLong);
    }
    if aad > MAX_AAD_BYTES {
        return Err(Error::AssociatedDataTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_length_limits() {
        assert_eq!(check_lengths(MAX_AAD_BYTES, MAX_MESSAGE_BYTES), Ok(()));
        assert_eq!(
            check_lengths(0, MAX_MESSAGE_BYTES + 1),
            Err(Error::MessageTooLong)
        );
        assert_eq!(
            check_lengths(MAX_AAD_BYTES + 1, 0),
            Err(Error::AssociatedDataTooLong)
        );
    }
}
