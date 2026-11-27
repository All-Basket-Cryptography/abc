#![no_std]
#![forbid(unsafe_code)]

//! RFC 7914 scrypt with explicit caller-owned memory.

use abc_pbkdf2_hmac_sha256::{derive as pbkdf2, Error as Pbkdf2Error, MAX_OUTPUT_BYTES};
use core::num::NonZeroU32;

const ONE: NonZeroU32 = NonZeroU32::MIN;
const SALSA_BYTES: usize = 64;
const BLOCK_FACTOR: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidParameters,
    MemorySize,
    WorkspaceTooSmall,
    Pbkdf2(Pbkdf2Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParameters => formatter.write_str("invalid RFC 7914 scrypt parameters"),
            Self::MemorySize => formatter.write_str("scrypt workspace size is not representable"),
            Self::WorkspaceTooSmall => {
                formatter.write_str("caller workspace is shorter than required")
            }
            Self::Pbkdf2(error) => error.fmt(formatter),
        }
    }
}

impl core::error::Error for Error {}

impl From<Pbkdf2Error> for Error {
    fn from(error: Pbkdf2Error) -> Self {
        Self::Pbkdf2(error)
    }
}

/// An admissible scrypt profile with a representable memory layout.
#[derive(Clone, Copy)]
pub struct Parameters {
    cost: usize,
    stride: usize,
    input_bytes: usize,
    table_bytes: usize,
    workspace_bytes: usize,
}

impl Parameters {
    /// Select RFC 7914's cost N, block size r and parallelization p.
    pub fn new(cost: usize, r: usize, p: usize) -> Result<Self, Error> {
        if cost <= 1
            || !cost.is_power_of_two()
            || r == 0
            || p == 0
            || cost.trailing_zeros() as usize >= r.saturating_mul(16)
        {
            return Err(Error::InvalidParameters);
        }
        let stride = BLOCK_FACTOR.checked_mul(r).ok_or(Error::MemorySize)?;
        let input_bytes = stride.checked_mul(p).ok_or(Error::MemorySize)?;
        if input_bytes as u64 > MAX_OUTPUT_BYTES {
            return Err(Error::InvalidParameters);
        }
        let table_bytes = stride.checked_mul(cost).ok_or(Error::MemorySize)?;
        let workspace_bytes = input_bytes
            .checked_add(table_bytes)
            .and_then(|total| total.checked_add(stride))
            .ok_or(Error::MemorySize)?;
        Ok(Self {
            cost,
            stride,
            input_bytes,
            table_bytes,
            workspace_bytes,
        })
    }

    /// Total bytes of input lanes, ROMix table and temporary BlockMix storage.
    pub const fn workspace_size(self) -> usize {
        self.workspace_bytes
    }
}

/// Derive a key using RFC 7914 with no implicit allocation.
///
/// The workspace contains password-derived material after return. The caller
/// owns its lifetime and erasure. Apply limits appropriate for the deployment
/// before using untrusted inputs to select the parameters.
pub fn derive(
    password: &[u8],
    salt: &[u8],
    parameters: Parameters,
    output: &mut [u8],
    workspace: &mut [u8],
) -> Result<(), Error> {
    if output.is_empty() || output.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(Pbkdf2Error::OutputLength.into());
    }
    let memory = workspace
        .get_mut(..parameters.workspace_size())
        .ok_or(Error::WorkspaceTooSmall)?;
    let (lanes, rest) = memory.split_at_mut(parameters.input_bytes);
    let (table, temporary) = rest.split_at_mut(parameters.table_bytes);
    pbkdf2(password, salt, ONE, lanes)?;
    for lane in lanes.chunks_exact_mut(parameters.stride) {
        romix(lane, table, temporary, parameters.cost);
    }
    pbkdf2(password, lanes, ONE, output)?;
    Ok(())
}

fn romix(lane: &mut [u8], table: &mut [u8], temporary: &mut [u8], cost: usize) {
    let stride = lane.len();
    for slot in table.chunks_exact_mut(stride) {
        slot.copy_from_slice(lane);
        block_mix(lane, temporary);
    }
    for _ in 0..cost {
        let last_block = &lane[stride - SALSA_BYTES..];
        let low = u64::from_le_bytes(last_block.as_chunks::<8>().0[0]);
        let index = low as usize & (cost - 1);
        for (value, sample) in lane.iter_mut().zip(&table[index * stride..][..stride]) {
            *value ^= sample;
        }
        block_mix(lane, temporary);
    }
}

fn block_mix(lane: &mut [u8], temporary: &mut [u8]) {
    let blocks = lane.len() / SALSA_BYTES;
    let mut words = [0u32; 16];
    let last = &lane[lane.len() - SALSA_BYTES..];
    for (word, bytes) in words.iter_mut().zip(last.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    for (index, block) in lane.chunks_exact(SALSA_BYTES).enumerate() {
        for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
            *word ^= u32::from_le_bytes(*bytes);
        }
        salsa8(&mut words);
        let destination = index / 2 + (index % 2) * (blocks / 2);
        let offset = destination * SALSA_BYTES;
        for (bytes, word) in temporary[offset..][..SALSA_BYTES]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(words)
        {
            *bytes = word.to_le_bytes();
        }
    }
    lane.copy_from_slice(temporary);
}

fn salsa_quarter(words: &mut [u32; 16], indices: [usize; 4]) {
    let [a, b, c, d] = indices;
    words[b] ^= words[a].wrapping_add(words[d]).rotate_left(7);
    words[c] ^= words[b].wrapping_add(words[a]).rotate_left(9);
    words[d] ^= words[c].wrapping_add(words[b]).rotate_left(13);
    words[a] ^= words[d].wrapping_add(words[c]).rotate_left(18);
}

fn salsa8(state: &mut [u32; 16]) {
    let mut words = *state;
    for _ in 0..4 {
        for column in 0..4 {
            salsa_quarter(
                &mut words,
                [
                    5 * column,
                    4 * ((column + 1) % 4) + column,
                    4 * ((column + 2) % 4) + column,
                    4 * ((column + 3) % 4) + column,
                ],
            );
        }
        for row in 0..4 {
            salsa_quarter(
                &mut words,
                [
                    5 * row,
                    4 * row + (row + 1) % 4,
                    4 * row + (row + 2) % 4,
                    4 * row + (row + 3) % 4,
                ],
            );
        }
    }
    for (output, word) in state.iter_mut().zip(words) {
        *output = output.wrapping_add(word);
    }
}
