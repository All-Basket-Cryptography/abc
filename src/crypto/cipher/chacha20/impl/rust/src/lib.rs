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

fn load_word(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) | ((b as u32) << 8u32) | ((c as u32) << 16u32) | ((d as u32) << 24u32)
}

fn initial_state(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES]) -> [u32; 16] {
    macro_rules! load {
        ($input:ident, $offset:literal) => {
            load_word(
                $input[$offset],
                $input[$offset + 1],
                $input[$offset + 2],
                $input[$offset + 3],
            )
        };
    }
    [
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
        load!(key, 0),
        load!(key, 4),
        load!(key, 8),
        load!(key, 12),
        load!(key, 16),
        load!(key, 20),
        load!(key, 24),
        load!(key, 28),
        0,
        load!(nonce, 0),
        load!(nonce, 4),
        load!(nonce, 8),
    ]
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

fn serialize(words: [u32; 16]) -> [u8; BLOCK_BYTES] {
    macro_rules! bytes {
        ($($lane:literal),+) => {
            [$(
                words[$lane] as u8,
                (words[$lane] >> 8u32) as u8,
                (words[$lane] >> 16u32) as u8,
                (words[$lane] >> 24u32) as u8,
            )+]
        };
    }
    bytes!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
}

fn block(initial: [u32; 16], counter: u32) -> [u8; BLOCK_BYTES] {
    serialize(block_words(initial, counter))
}

fn counter_exhausted(length: usize, counter: u32) -> bool {
    if length == 0 {
        return false;
    }
    // Compare the final block's offset from the starting counter.
    let last = (length - 1) / BLOCK_BYTES;
    last as u64 > 0xffff_ffffu64 - counter as u64
}

fn xor_byte(input: &mut [u8], index: usize, pad: u8) {
    input[index] ^= pad;
}

fn xor_block(input: &mut [u8], start: usize, pad: &[u8; BLOCK_BYTES]) -> usize {
    let remaining = input.len() - start;
    let length = if remaining < BLOCK_BYTES {
        remaining
    } else {
        BLOCK_BYTES
    };
    let mut index = 0;
    while index < length {
        xor_byte(input, start + index, pad[index]);
        index += 1;
    }
    start + length
}

/// XOR an entire message with its keystream. Counter exhaustion preserves the
/// input. Callers own nonce allocation for each key and protocol authentication.
pub fn apply_keystream(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    counter: u32,
    input: &mut [u8],
) -> Result<(), CounterExhausted> {
    if counter_exhausted(input.len(), counter) {
        return Err(CounterExhausted);
    }
    let initial = initial_state(key, nonce);
    let mut offset = 0;
    while offset < input.len() {
        let index = (offset / BLOCK_BYTES) as u32;
        let pad = block(initial, counter + index);
        offset = xor_block(input, offset, &pad);
    }
    Ok(())
}
