#![no_std]
#![forbid(unsafe_code)]
//! Unkeyed sequential BLAKE2b with a caller-selected output size.

pub const BLOCK_BYTES: usize = 128;
pub const MAX_DIGEST_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidDigestLength,
    OutputLengthMismatch,
    MessageTooLong,
}

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

pub struct Blake2b {
    chaining: [u64; 8],
    pending: [u8; BLOCK_BYTES],
    buffered: usize,
    length: u128,
    output_size: usize,
}

impl Blake2b {
    /// Choose a fixed digest length from 1 through 64 bytes.
    pub const fn new(output_size: usize) -> Result<Self, Error> {
        if output_size == 0 || output_size > MAX_DIGEST_BYTES {
            return Err(Error::InvalidDigestLength);
        }
        let mut chaining = IV;
        chaining[0] ^= 0x0101_0000 | output_size as u64;
        Ok(Self {
            chaining,
            pending: [0; BLOCK_BYTES],
            buffered: 0,
            length: 0,
            output_size,
        })
    }

    /// Append bytes. An update outside the 128-bit byte counter leaves the context unchanged.
    pub fn update(&mut self, mut input: &[u8]) -> Result<(), Error> {
        let length = self
            .length
            .checked_add(input.len() as u128)
            .ok_or(Error::MessageTooLong)?;
        if input.is_empty() {
            return Ok(());
        }

        let mut compressed = self.length - self.buffered as u128;
        self.length = length;
        if self.buffered != 0 {
            let copied = input.len().min(BLOCK_BYTES - self.buffered);
            self.pending[self.buffered..self.buffered + copied].copy_from_slice(&input[..copied]);
            self.buffered += copied;
            input = &input[copied..];
            if input.is_empty() {
                return Ok(());
            }
            compressed += BLOCK_BYTES as u128;
            compress(&mut self.chaining, &self.pending, compressed, false);
        }
        // A complete final block must remain buffered until more bytes arrive.
        while let Some((block, remainder)) = input.split_first_chunk::<BLOCK_BYTES>() {
            if remainder.is_empty() {
                break;
            }
            compressed += BLOCK_BYTES as u128;
            compress(&mut self.chaining, block, compressed, false);
            input = remainder;
        }
        self.pending[..input.len()].copy_from_slice(input);
        self.buffered = input.len();
        Ok(())
    }

    /// Write a digest snapshot. The output slice must match the selected size exactly.
    pub fn finalize(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != self.output_size {
            return Err(Error::OutputLengthMismatch);
        }
        let mut block = [0; BLOCK_BYTES];
        block[..self.buffered].copy_from_slice(&self.pending[..self.buffered]);
        let mut chaining = self.chaining;
        compress(&mut chaining, &block, self.length, true);

        for (chunk, word) in output.chunks_mut(8).zip(chaining) {
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

/// Hash a byte slice into a caller-owned digest of 1 through 64 bytes.
pub fn digest(input: &[u8], output: &mut [u8]) -> Result<(), Error> {
    let mut context = Blake2b::new(output.len())?;
    context.update(input)?;
    context.finalize(output)
}

fn mix(v: &mut [u64; 16], [a, b, c, d]: [usize; 4], x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(chaining: &mut [u64; 8], block: &[u8; BLOCK_BYTES], count: u128, final_block: bool) {
    let mut words = [0; 16];
    for (word, bytes) in words.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*bytes);
    }
    let mut v = [0; 16];
    v[..8].copy_from_slice(chaining);
    v[8..].copy_from_slice(&IV);
    v[12] ^= count as u64;
    v[13] ^= (count >> 64) as u64;
    if final_block {
        v[14] = !v[14];
    }

    for round in 0..12 {
        let s = SIGMA[round % SIGMA.len()];
        mix(&mut v, [0, 4, 8, 12], words[s[0]], words[s[1]]);
        mix(&mut v, [1, 5, 9, 13], words[s[2]], words[s[3]]);
        mix(&mut v, [2, 6, 10, 14], words[s[4]], words[s[5]]);
        mix(&mut v, [3, 7, 11, 15], words[s[6]], words[s[7]]);
        mix(&mut v, [0, 5, 10, 15], words[s[8]], words[s[9]]);
        mix(&mut v, [1, 6, 11, 12], words[s[10]], words[s[11]]);
        mix(&mut v, [2, 7, 8, 13], words[s[12]], words[s[13]]);
        mix(&mut v, [3, 4, 9, 14], words[s[14]], words[s[15]]);
    }
    for (i, word) in chaining.iter_mut().enumerate() {
        *word ^= v[i] ^ v[i + 8];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_counter_overflow_without_mutating_context() {
        let mut ctx = Blake2b::new(1).unwrap();
        ctx.length = u128::MAX - 1;
        ctx.buffered = 126;
        ctx.update(b"a").unwrap();
        assert_eq!(ctx.length, u128::MAX);
        let state = (ctx.length, ctx.buffered, ctx.pending, ctx.chaining);
        assert_eq!(ctx.update(b"z"), Err(Error::MessageTooLong));
        assert_eq!((ctx.length, ctx.buffered, ctx.pending, ctx.chaining), state);
        assert_eq!(ctx.update(b""), Ok(()));
    }
}
