#![no_std]
#![forbid(unsafe_code)]
//! Byte-oriented SHA-512, as specified by FIPS 180-4.

const BLOCK_BYTES: usize = 128;
const LENGTH_START: usize = 112;
pub const DIGEST_BYTES: usize = 64;
pub const MAX_MESSAGE_BYTES: u128 = u128::MAX / 8;

// FIPS 180-4 § 5.3.5: fractional bits of square roots of the first 8 primes.
#[rustfmt::skip]
const INITIAL_STATE: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

// FIPS 180-4 § 4.2.3: fractional bits of cube roots of the first 80 primes.
#[rustfmt::skip]
const ROUND_CONSTANTS: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageTooLong;

impl core::fmt::Display for MessageTooLong {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SHA-512 message exceeds the 128-bit bit-length domain")
    }
}

impl core::error::Error for MessageTooLong {}

/// Byte-oriented SHA-512 context. Caller buffers can be reused after update.
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    block: [u8; BLOCK_BYTES],
    buffered: usize,
    bytes: u128,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    pub const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            block: [0; BLOCK_BYTES],
            buffered: 0,
            bytes: 0,
        }
    }

    /// Append bytes. Length rejection leaves the context unchanged.
    pub fn update(&mut self, mut input: &[u8]) -> Result<(), MessageTooLong> {
        let incoming = input.len() as u128;
        if incoming > MAX_MESSAGE_BYTES - self.bytes {
            return Err(MessageTooLong);
        }
        self.bytes += incoming;

        if self.buffered != 0 {
            let copied = input.len().min(BLOCK_BYTES - self.buffered);
            let end = self.buffered + copied;
            self.block[self.buffered..end].copy_from_slice(&input[..copied]);
            self.buffered = end;
            if end < BLOCK_BYTES {
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

    pub fn finalize(mut self) -> [u8; DIGEST_BYTES] {
        self.block[self.buffered] = 0x80;
        self.block[self.buffered + 1..].fill(0);
        if self.buffered >= LENGTH_START {
            compress(&mut self.state, &self.block);
            self.block.fill(0);
        }
        self.block[LENGTH_START..].copy_from_slice(&(self.bytes * 8).to_be_bytes());
        compress(&mut self.state, &self.block);

        let mut digest = [0; DIGEST_BYTES];
        for (chunk, word) in digest.as_chunks_mut::<8>().0.iter_mut().zip(self.state) {
            *chunk = word.to_be_bytes();
        }
        digest
    }
}

pub fn digest(input: &[u8]) -> Result<[u8; DIGEST_BYTES], MessageTooLong> {
    let mut state = Sha512::new();
    state.update(input)?;
    Ok(state.finalize())
}

fn compress(state: &mut [u64; 8], block: &[u8; BLOCK_BYTES]) {
    let mut words = [0u64; 80];
    for (word, chunk) in words.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*chunk);
    }
    for i in 16..80 {
        let x = words[i - 15];
        let y = words[i - 2];
        let lower0 = x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7);
        let lower1 = y.rotate_right(19) ^ y.rotate_right(61) ^ (y >> 6);
        words[i] = lower1
            .wrapping_add(words[i - 7])
            .wrapping_add(lower0)
            .wrapping_add(words[i - 16]);
    }

    let mut work = *state;
    for (constant, word) in ROUND_CONSTANTS.into_iter().zip(words) {
        let [a, b, c, d, e, f, g, h] = work;
        let upper1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let choose = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(upper1)
            .wrapping_add(choose)
            .wrapping_add(constant)
            .wrapping_add(word);
        let upper0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = upper0.wrapping_add(majority);
        work = [
            temp1.wrapping_add(temp2),
            a,
            b,
            c,
            d.wrapping_add(temp1),
            e,
            f,
            g,
        ];
    }
    for (word, working) in state.iter_mut().zip(work) {
        *word = word.wrapping_add(working);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_preserves_context() {
        let mut state = Sha512::new();
        state.bytes = MAX_MESSAGE_BYTES - 1;
        state.buffered = 126;
        assert_eq!(state.update(&[1]), Ok(()));
        let expected = state.clone().finalize();
        assert_eq!(state.update(&[2]), Err(MessageTooLong));
        assert_eq!(state.update(&[]), Ok(()));
        assert_eq!(state.finalize(), expected);
    }
}
