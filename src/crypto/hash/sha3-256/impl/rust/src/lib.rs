#![no_std]
#![forbid(unsafe_code)]

//! Byte-oriented SHA3-256 as specified in FIPS 202, sections 3 through 6.

use abc_keccak_p1600::{absorb_rate_block, RATE_BYTES};

const DIGEST_BYTES: usize = 32;

/// Digest a byte string and return the 32 bytes of the FIPS 202 SHA3-256 result.
pub fn digest(message: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut state = [0u64; 25];
    let blocks = message.as_chunks::<RATE_BYTES>();
    for block in blocks.0 {
        absorb_rate_block(&mut state, block);
    }

    let tail = blocks.1;
    let mut padded = [0; RATE_BYTES];
    padded[..tail.len()].copy_from_slice(tail);
    // Byte-aligned encoding of the SHA-3 domain bits followed by pad10*1.
    padded[tail.len()] = 0x06;
    padded[RATE_BYTES - 1] |= 0x80;
    absorb_rate_block(&mut state, &padded);

    let mut output = [0; DIGEST_BYTES];
    for (chunk, lane) in output.as_chunks_mut::<8>().0.iter_mut().zip(state) {
        *chunk = lane.to_le_bytes();
    }
    output
}
