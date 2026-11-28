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
        let incoming = input.len() as u64;
        if incoming as usize != input.len() || incoming > MAX_MESSAGE_BYTES - self.length {
            return Err(MessageTooLong);
        }
        self.length += incoming;

        if self.buffered != 0 {
            let mut copied = 0;
            while self.buffered < BLOCK_BYTES && copied < input.len() {
                self.block[self.buffered] = input[copied];
                self.buffered += 1;
                copied += 1;
            }
            if self.buffered < BLOCK_BYTES {
                return Ok(());
            }
            self.state = compress(self.state, &self.block);
            input = &input[copied..];
        }

        while input.len() >= BLOCK_BYTES {
            self.state = compress(self.state, &input[..BLOCK_BYTES]);
            input = &input[BLOCK_BYTES..];
        }
        self.buffered = 0;
        while self.buffered < input.len() {
            self.block[self.buffered] = input[self.buffered];
            self.buffered += 1;
        }
        Ok(())
    }

    /// Append SHA-256 padding and return the digest in big-endian byte order.
    pub fn finalize(mut self) -> [u8; DIGEST_BYTES] {
        self.block[self.buffered] = 0x80;
        let mut i = self.buffered + 1;
        while i < BLOCK_BYTES {
            self.block[i] = 0;
            i += 1;
        }
        if self.buffered >= 56 {
            self.state = compress(self.state, &self.block);
            self.block = [0; BLOCK_BYTES];
        }
        let length_bytes = (self.length * 8).to_be_bytes();
        let mut i = 0;
        while i < 8 {
            self.block[56 + i] = length_bytes[i];
            i += 1;
        }
        self.state = compress(self.state, &self.block);

        let mut digest = [0; DIGEST_BYTES];
        let mut i = 0;
        while i < self.state.len() {
            let [a, b, c, d] = self.state[i].to_be_bytes();
            let offset = 4 * i;
            digest[offset] = a;
            digest[offset + 1] = b;
            digest[offset + 2] = c;
            digest[offset + 3] = d;
            i += 1;
        }
        digest
    }
}

pub fn digest(message: &[u8]) -> Result<[u8; DIGEST_BYTES], MessageTooLong> {
    let mut hasher = Sha256::new();
    hasher.update(message)?;
    Ok(hasher.finalize())
}

fn compress(state: [u32; 8], block: &[u8]) -> [u32; 8] {
    let mut words = [0u32; 64];
    let mut i = 0;
    while i < 16 {
        let offset = 4 * i;
        words[i] = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
        i += 1;
    }
    while i < 64 {
        words[i] = schedule_word(words[i - 16], words[i - 15], words[i - 7], words[i - 2]);
        i += 1;
    }

    let mut work = state;
    let mut i = 0;
    while i < 64 {
        work = round_step(work, ROUND_CONSTANTS[i], words[i]);
        i += 1;
    }

    feed_forward(state, work)
}

fn schedule_word(w16: u32, w15: u32, w7: u32, w2: u32) -> u32 {
    let sigma0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
    let sigma1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
    w16.wrapping_add(sigma0)
        .wrapping_add(w7)
        .wrapping_add(sigma1)
}

fn round_step(state: [u32; 8], constant: u32, word: u32) -> [u32; 8] {
    let [a, b, c, d, e, f, g, h] = state;
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
    [
        temp1.wrapping_add(temp2),
        a,
        b,
        c,
        d.wrapping_add(temp1),
        e,
        f,
        g,
    ]
}

fn feed_forward(state: [u32; 8], work: [u32; 8]) -> [u32; 8] {
    let [a, b, c, d, e, f, g, h] = state;
    let [wa, wb, wc, wd, we, wf, wg, wh] = work;
    [
        a.wrapping_add(wa),
        b.wrapping_add(wb),
        c.wrapping_add(wc),
        d.wrapping_add(wd),
        e.wrapping_add(we),
        f.wrapping_add(wf),
        g.wrapping_add(wg),
        h.wrapping_add(wh),
    ]
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
