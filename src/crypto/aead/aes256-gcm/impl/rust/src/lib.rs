#![no_std]
#![forbid(unsafe_code)]
//! SP 800-38D research profile with 96-bit nonces and detached 128-bit tags.

use abc_aes256::{Aes256, BLOCK_BYTES};

pub use abc_aes256::KEY_BYTES;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;
pub const MAX_MESSAGE_BYTES: u64 = (u32::MAX as u64 - 1) * BLOCK_BYTES as u64;
pub const MAX_AAD_BYTES: u64 = u64::MAX / 8;

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

/// Use a unique nonce for each encryption under the key.
pub fn seal_in_place(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; TAG_BYTES], Error> {
    check_lengths(aad.len() as u64, data.len() as u64)?;
    let aes = Aes256::new(key);
    apply_payload(&aes, nonce, data);
    Ok(authenticate(&aes, nonce, aad, data))
}

/// Verify the tag before decrypting the payload. Rejection preserves the input.
pub fn open_in_place(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_BYTES],
) -> Result<(), Error> {
    check_lengths(aad.len() as u64, data.len() as u64)?;
    let aes = Aes256::new(key);
    let actual = authenticate(&aes, nonce, aad, data);
    let mut diff = 0u8;
    for (a, b) in actual.into_iter().zip(tag) {
        diff |= a ^ b;
    }
    if core::hint::black_box(diff) != 0 {
        return Err(Error::AuthenticationFailed);
    }
    apply_payload(&aes, nonce, data);
    Ok(())
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

fn encrypt_counter(aes: &Aes256, nonce: &[u8; NONCE_BYTES], counter: u32) -> [u8; BLOCK_BYTES] {
    let mut block = [0; BLOCK_BYTES];
    block[..NONCE_BYTES].copy_from_slice(nonce);
    block[NONCE_BYTES..].copy_from_slice(&counter.to_be_bytes());
    aes.encrypt(&mut block);
    block
}

fn apply_payload(aes: &Aes256, nonce: &[u8; NONCE_BYTES], data: &mut [u8]) {
    for (index, chunk) in data.chunks_mut(BLOCK_BYTES).enumerate() {
        let stream = encrypt_counter(aes, nonce, 2 + index as u32);
        for (byte, pad) in chunk.iter_mut().zip(stream) {
            *byte ^= pad;
        }
    }
}

fn authenticate(
    aes: &Aes256,
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    data: &[u8],
) -> [u8; TAG_BYTES] {
    let mut zero = [0; BLOCK_BYTES];
    aes.encrypt(&mut zero);
    let hash_key = u128::from_be_bytes(zero);
    let mut state = 0;
    hash_padded(hash_key, &mut state, aad);
    hash_padded(hash_key, &mut state, data);
    let lengths = pack_lengths(aad.len() as u64, data.len() as u64);
    let tag_mask = u128::from_be_bytes(encrypt_counter(aes, nonce, 1));
    finish_tag(hash_key, state, lengths, tag_mask).to_be_bytes()
}

fn hash_padded(hash_key: u128, state: &mut u128, input: &[u8]) {
    let (blocks, tail) = input.as_chunks::<BLOCK_BYTES>();
    for block in blocks {
        *state = hash_block(hash_key, *state, u128::from_be_bytes(*block));
    }
    if !tail.is_empty() {
        let mut padded = [0; BLOCK_BYTES];
        padded[..tail.len()].copy_from_slice(tail);
        *state = hash_block(hash_key, *state, u128::from_be_bytes(padded));
    }
}

fn hash_block(hash_key: u128, state: u128, block: u128) -> u128 {
    multiply(state ^ block, hash_key)
}

fn pack_lengths(aad_bytes: u64, data_bytes: u64) -> u128 {
    ((aad_bytes as u128 * 8) << 64u32) | (data_bytes as u128 * 8)
}

fn finish_tag(hash_key: u128, state: u128, lengths: u128, tag_mask: u128) -> u128 {
    hash_block(hash_key, state, lengths) ^ tag_mask
}

fn multiply(input: u128, mut key: u128) -> u128 {
    let mut product = 0;
    let mut bit = 128u32;
    while bit != 0 {
        bit -= 1;
        product ^= key & 0u128.wrapping_sub((input >> bit) & 1);
        // The high byte contains the reflected reduction polynomial.
        key = (key >> 1u32) ^ (0xe1000000000000000000000000000000 & 0u128.wrapping_sub(key & 1));
    }
    product
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_limits() {
        assert_eq!(check_lengths(MAX_AAD_BYTES, MAX_MESSAGE_BYTES), Ok(()));
        assert_eq!(
            check_lengths(MAX_AAD_BYTES + 1, 0),
            Err(Error::AssociatedDataTooLong)
        );
        assert_eq!(
            check_lengths(0, MAX_MESSAGE_BYTES + 1),
            Err(Error::MessageTooLong)
        );
    }
}
