#![no_std]
#![forbid(unsafe_code)]

//! Portable IETF ChaCha20 primitive for research and composition.

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const BLOCK_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterExhausted;

impl core::fmt::Display for CounterExhausted {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ChaCha20 block count exceeds the 32-bit counter domain")
    }
}

impl core::error::Error for CounterExhausted {}

fn quarter_round(state: &mut [u32; 16], indices: [usize; 4]) {
    let [a, b, c, d] = indices;
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn initial_state(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES]) -> [u32; 16] {
    let mut state = [0; 16];
    state[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for (word, bytes) in state[4..12].iter_mut().zip(key.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    for (word, bytes) in state[13..].iter_mut().zip(nonce.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    state
}

fn double_round(mut state: [u32; 16]) -> [u32; 16] {
    quarter_round(&mut state, [0, 4, 8, 12]);
    quarter_round(&mut state, [1, 5, 9, 13]);
    quarter_round(&mut state, [2, 6, 10, 14]);
    quarter_round(&mut state, [3, 7, 11, 15]);
    quarter_round(&mut state, [0, 5, 10, 15]);
    quarter_round(&mut state, [1, 6, 11, 12]);
    quarter_round(&mut state, [2, 7, 8, 13]);
    quarter_round(&mut state, [3, 4, 9, 14]);
    state
}

// Spell out the fixed call schedule so each step is visible to extraction.
fn rounds_20(mut state: [u32; 16]) -> [u32; 16] {
    state = double_round(state);
    state = double_round(state);
    state = double_round(state);
    state = double_round(state);
    state = double_round(state);
    state = double_round(state);
    state = double_round(state);
    state = double_round(state);
    state = double_round(state);
    double_round(state)
}

fn block_words(mut initial: [u32; 16], counter: u32) -> [u32; 16] {
    initial[12] = counter;
    let state = rounds_20(initial);
    macro_rules! add_initial {
        ($($lane:literal),+) => {
            [$(state[$lane].wrapping_add(initial[$lane])),+]
        };
    }
    add_initial!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
}

fn block(initial: [u32; 16], counter: u32) -> [u8; BLOCK_BYTES] {
    let words = block_words(initial, counter);
    let mut bytes = [0; BLOCK_BYTES];
    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }
    bytes
}

/// XOR an entire message with its keystream. Counter exhaustion preserves the
/// input. Callers own nonce allocation for each key and protocol authentication.
pub fn apply_keystream(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    counter: u32,
    input: &mut [u8],
) -> Result<(), CounterExhausted> {
    let blocks = input.len().div_ceil(BLOCK_BYTES) as u64;
    if blocks > (1u64 << 32) - u64::from(counter) {
        return Err(CounterExhausted);
    }
    let initial = initial_state(key, nonce);
    for (index, chunk) in input.chunks_mut(BLOCK_BYTES).enumerate() {
        for (byte, stream_byte) in chunk.iter_mut().zip(block(initial, counter + index as u32)) {
            *byte ^= stream_byte;
        }
    }
    Ok(())
}
