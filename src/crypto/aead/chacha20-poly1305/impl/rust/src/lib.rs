#![no_std]
#![forbid(unsafe_code)]
//! Research implementation of the RFC 8439 IETF AEAD composition.

use abc_chacha20::{apply_keystream, BLOCK_BYTES};
use abc_poly1305::Poly1305;

pub use abc_chacha20::{KEY_BYTES, NONCE_BYTES};
pub use abc_poly1305::TAG_BYTES;

pub const MAX_MESSAGE_BYTES: u64 = u32::MAX as u64 * BLOCK_BYTES as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    MessageTooLong,
    AuthenticationFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::MessageTooLong => "AEAD message exhausts the 32-bit counter domain",
            Self::AuthenticationFailed => "AEAD tag verification failed",
        })
    }
}

impl core::error::Error for Error {}

fn authenticate(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    encrypted: &[u8],
) -> Result<[u8; TAG_BYTES], Error> {
    let mut one_time_key = [0; abc_poly1305::KEY_BYTES];
    apply_keystream(key, nonce, 0, &mut one_time_key).map_err(|_| Error::MessageTooLong)?;
    let mut mac = Poly1305::new(&one_time_key);
    add_padded(&mut mac, aad);
    add_padded(&mut mac, encrypted);
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(encrypted.len() as u64).to_le_bytes());
    Ok(mac.finalize())
}

fn add_padded(mac: &mut Poly1305, input: &[u8]) {
    const ZERO: [u8; 16] = [0; 16];
    mac.update(input);
    mac.update(&ZERO[..(16 - input.len() % 16) % 16]);
}

fn check_length(length: usize) -> Result<(), Error> {
    if length as u64 > MAX_MESSAGE_BYTES {
        Err(Error::MessageTooLong)
    } else {
        Ok(())
    }
}

/// Replace plaintext with ciphertext and return the detached tag.
/// Callers must allocate a unique nonce for each encryption under this key.
pub fn seal_in_place(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; TAG_BYTES], Error> {
    check_length(data.len())?;
    apply_keystream(key, nonce, 1, data).map_err(|_| Error::MessageTooLong)?;
    authenticate(key, nonce, aad, data)
}

/// Verify the full tag before decrypting. A rejected tag leaves bytes unchanged.
pub fn open_in_place(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_BYTES],
) -> Result<(), Error> {
    check_length(data.len())?;
    let actual = authenticate(key, nonce, aad, data)?;
    let mut difference = 0u8;
    for (candidate, expected) in actual.iter().zip(tag) {
        difference |= candidate ^ expected;
    }
    if core::hint::black_box(difference) != 0 {
        return Err(Error::AuthenticationFailed);
    }
    apply_keystream(key, nonce, 1, data).map_err(|_| Error::MessageTooLong)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_matches_last_counter() {
        if let Ok(limit) = usize::try_from(MAX_MESSAGE_BYTES) {
            assert_eq!(check_length(limit), Ok(()));
            assert_eq!(check_length(limit + 1), Err(Error::MessageTooLong));
        }
    }
}
