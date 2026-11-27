#![no_std]
#![forbid(unsafe_code)]
//! Portable byte-oriented SHA-256, specified by FIPS 180-4 sections 4–6.

use core::fmt;

const BLOCK_BYTES: usize = 64;
pub const DIGEST_BYTES: usize = 32;
pub const MAX_MESSAGE_BYTES: u64 = u64::MAX / 8;
pub const IMPLEMENTATION_ID: &str = "sha256-abc-rust-portable";

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[rustfmt::skip]
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The total byte length would reach or exceed 2^64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageTooLong;

impl fmt::Display for MessageTooLong {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("SHA-256 message exceeds the maximum byte length")
    }
}

impl core::error::Error for MessageTooLong {}

/// An in-progress digest. Chunks are copied or processed during `update`.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; BLOCK_BYTES],
    buffered: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            block: [0; BLOCK_BYTES],
            buffered: 0,
            length: 0,
        }
    }

    /// Append bytes. Overflow leaves the existing state unchanged.
    pub fn update(&mut self, mut input: &[u8]) -> Result<(), MessageTooLong> {
        let incoming = u64::try_from(input.len()).map_err(|_| MessageTooLong)?;
        self.length = self
            .length
            .checked_add(incoming)
            .filter(|total| *total <= MAX_MESSAGE_BYTES)
            .ok_or(MessageTooLong)?;

        if self.buffered != 0 {
            let copied = (BLOCK_BYTES - self.buffered).min(input.len());
            self.block[self.buffered..self.buffered + copied].copy_from_slice(&input[..copied]);
            self.buffered += copied;
            if self.buffered < BLOCK_BYTES {
                return Ok(());
            }
            compress(&mut self.state, &self.block);
            input = &input[copied..];
        }

        let (blocks, tail) = input.as_chunks::<BLOCK_BYTES>();
        for block in blocks {
            compress(&mut self.state, block);
        }
        self.block[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
        Ok(())
    }

    /// Append SHA-256 padding and return the digest in big-endian byte order.
    pub fn finalize(mut self) -> [u8; DIGEST_BYTES] {
        self.block[self.buffered] = 0x80;
        self.block[self.buffered + 1..].fill(0);
        if self.buffered >= 56 {
            compress(&mut self.state, &self.block);
            self.block.fill(0);
        }
        self.block[56..].copy_from_slice(&(self.length * 8).to_be_bytes());
        compress(&mut self.state, &self.block);

        let mut digest = [0; DIGEST_BYTES];
        for (bytes, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *bytes = word.to_be_bytes();
        }
        digest
    }
}

pub fn digest(message: &[u8]) -> Result<[u8; DIGEST_BYTES], MessageTooLong> {
    let mut hasher = Sha256::new();
    hasher.update(message)?;
    Ok(hasher.finalize())
}

fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_BYTES]) {
    let mut words = [0u32; 64];
    for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    for round in 16..64 {
        let x = words[round - 15];
        let y = words[round - 2];
        let sigma0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
        let sigma1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
        words[round] = words[round - 16]
            .wrapping_add(sigma0)
            .wrapping_add(words[round - 7])
            .wrapping_add(sigma1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (constant, word) in ROUND_CONSTANTS.into_iter().zip(words) {
        let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(sigma1)
            .wrapping_add(choose)
            .wrapping_add(constant)
            .wrapping_add(word);
        let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sigma0.wrapping_add(majority);

        (a, b, c, d, e, f, g, h) = (
            temp1.wrapping_add(temp2),
            a,
            b,
            c,
            d.wrapping_add(temp1),
            e,
            f,
            g,
        );
    }
    for (value, addition) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *value = value.wrapping_add(addition);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_does_not_mutate_state() {
        let mut hasher = Sha256::new();
        hasher.length = MAX_MESSAGE_BYTES - 1;
        hasher.buffered = 62;
        assert_eq!(hasher.update(&[1]), Ok(()));
        let expected = hasher.clone().finalize();
        assert_eq!(hasher.update(&[2]), Err(MessageTooLong));
        assert_eq!(hasher.update(&[]), Ok(()));
        assert_eq!(hasher.finalize(), expected);
    }
}
