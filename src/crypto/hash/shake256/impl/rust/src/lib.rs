#![no_std]
#![forbid(unsafe_code)]
//! Streaming byte-oriented SHAKE256, as specified by FIPS 202.

use abc_keccak_p1600::{absorb_rate_block, keccak_p1600, RATE_BYTES};

/// An absorber for arbitrary byte chunks.
#[derive(Clone)]
pub struct Shake256 {
    lanes: [u64; 25],
    block: [u8; RATE_BYTES],
    buffered: usize,
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake256 {
    pub const fn new() -> Self {
        Self {
            lanes: [0; 25],
            block: [0; RATE_BYTES],
            buffered: 0,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        if self.buffered != 0 {
            let copied = input.len().min(RATE_BYTES - self.buffered);
            let end = self.buffered + copied;
            self.block[self.buffered..end].copy_from_slice(&input[..copied]);
            self.buffered = end;
            if end < RATE_BYTES {
                return;
            }
            absorb_rate_block(&mut self.lanes, &self.block);
            input = &input[copied..];
        }
        let (blocks, tail) = input.as_chunks::<RATE_BYTES>();
        for block in blocks {
            absorb_rate_block(&mut self.lanes, block);
        }
        self.block[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
    }

    /// Apply the SHAKE domain and padding, then switch to output mode.
    pub fn finalize(mut self) -> Reader {
        self.block[self.buffered..].fill(0);
        self.block[self.buffered] = 0x1f;
        self.block[RATE_BYTES - 1] |= 0x80;
        absorb_rate_block(&mut self.lanes, &self.block);
        let mut reader = Reader {
            lanes: self.lanes,
            block: self.block,
            offset: 0,
        };
        reader.encode_block();
        reader
    }
}

/// A reader of the SHAKE256 output stream after final absorption.
pub struct Reader {
    lanes: [u64; 25],
    block: [u8; RATE_BYTES],
    offset: usize,
}

impl Reader {
    fn encode_block(&mut self) {
        for (chunk, lane) in self
            .block
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(&self.lanes)
        {
            *chunk = lane.to_le_bytes();
        }
    }

    /// Fill caller-owned storage and advance the stream by its length.
    pub fn read(&mut self, mut output: &mut [u8]) {
        while !output.is_empty() {
            if self.offset == RATE_BYTES {
                keccak_p1600(&mut self.lanes);
                self.encode_block();
                self.offset = 0;
            }
            let length = output.len().min(RATE_BYTES - self.offset);
            let (destination, rest) = output.split_at_mut(length);
            destination.copy_from_slice(&self.block[self.offset..self.offset + length]);
            self.offset += length;
            output = rest;
        }
    }
}

pub fn xof(input: &[u8], output: &mut [u8]) {
    let mut state = Shake256::new();
    state.update(input);
    state.finalize().read(output);
}
