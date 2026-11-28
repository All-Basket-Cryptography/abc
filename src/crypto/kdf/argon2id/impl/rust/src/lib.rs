#![no_std]
#![forbid(unsafe_code)]
//! RFC 9106 Argon2id v1.3 with serial lanes and caller-owned workspace.

mod compress;
mod matrix;

use abc_blake2b::{digest, Blake2b};
use core::fmt;

pub const BLOCK_BYTES: usize = 1024;
pub const BLOCK_WORDS: usize = BLOCK_BYTES / size_of::<u64>();
pub const MIN_SALT_BYTES: usize = 8;
pub const MIN_TAG_BYTES: usize = 4;
pub const MAX_LANES: u32 = (1 << 24) - 1;
const VERSION: u32 = 0x13;
const VARIANT: u32 = 2;
const SLICES: usize = 4;

/// A workspace block with words stored in the host's native representation.
pub type Block = [u64; BLOCK_WORDS];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidParameters,
    WorkspaceSize,
    WorkspaceTooSmall,
    InputTooLong,
    SaltTooShort,
    InvalidTagLength,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidParameters => "invalid Argon2id memory, pass or lane parameters",
            Self::WorkspaceSize => "Argon2id workspace cannot be represented as a Rust block slice",
            Self::WorkspaceTooSmall => "caller workspace is shorter than required",
            Self::InputTooLong => "Argon2id input length exceeds its 32-bit encoding",
            Self::SaltTooShort => "the Argon2id profile requires a salt of at least eight bytes",
            Self::InvalidTagLength => "Argon2id tag length must be between four and 2^32 - 1 bytes",
        })
    }
}

impl core::error::Error for Error {}

/// A validated cost profile and its rounded workspace dimensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    memory_kib: u32,
    iterations: u32,
    lanes: usize,
    segment_blocks: usize,
    block_count: usize,
}

impl Parameters {
    pub fn new(memory_kib: u32, iterations: u32, lanes: u32) -> Result<Self, Error> {
        if lanes == 0 || lanes > MAX_LANES || iterations == 0 || memory_kib < 8 * lanes {
            return Err(Error::InvalidParameters);
        }
        let slices = SLICES as u32 * lanes;
        let segment_blocks = memory_kib / slices;
        // Rounding down makes this product at most memory_kib.
        let block_count = segment_blocks * slices;
        if u64::from(block_count) * BLOCK_BYTES as u64 > isize::MAX as u64 {
            return Err(Error::WorkspaceSize);
        }
        Ok(Self {
            memory_kib,
            iterations,
            lanes: lanes as usize,
            segment_blocks: segment_blocks as usize,
            block_count: block_count as usize,
        })
    }

    /// Size of the caller's workspace in 1 KiB blocks.
    pub const fn workspace_blocks(self) -> usize {
        self.block_count
    }

    const fn lane_blocks(self) -> usize {
        self.segment_blocks * SLICES
    }
}

/// Derive an Argon2id tag. Empty secret and associated data represent omission.
///
/// Validation failures preserve both output and workspace. Extra workspace
/// blocks are untouched. The caller owns work limits and erasure for the
/// workspace, which retains inputs derived from the password after return.
pub fn derive(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    parameters: Parameters,
    output: &mut [u8],
    workspace: &mut [Block],
) -> Result<(), Error> {
    let inputs = [password, salt, secret, associated_data];
    let tag_length = validate_lengths(inputs.map(|input| input.len()), output.len())?;
    let matrix = workspace
        .get_mut(..parameters.workspace_blocks())
        .ok_or(Error::WorkspaceTooSmall)?;

    let h0 = prehash(parameters, tag_length, inputs);
    matrix::initialize(matrix, parameters, &h0);
    for pass in 0..parameters.iterations {
        matrix::fill_pass(matrix, parameters, pass);
    }
    let mut final_block = [0; BLOCK_WORDS];
    for lane in matrix.chunks_exact(parameters.lane_blocks()) {
        for (word, end) in final_block
            .iter_mut()
            .zip(lane[parameters.lane_blocks() - 1])
        {
            *word ^= end;
        }
    }
    let mut final_bytes = [0; BLOCK_BYTES];
    for (word, bytes) in final_block
        .into_iter()
        .zip(final_bytes.as_chunks_mut::<8>().0)
    {
        *bytes = word.to_le_bytes();
    }
    long_hash(&final_bytes, output);
    Ok(())
}

fn validate_lengths(input_lengths: [usize; 4], tag_length: usize) -> Result<u32, Error> {
    if input_lengths
        .iter()
        .any(|&length| u32::try_from(length).is_err())
    {
        return Err(Error::InputTooLong);
    }
    if input_lengths[1] < MIN_SALT_BYTES {
        return Err(Error::SaltTooShort);
    }
    if tag_length < MIN_TAG_BYTES {
        return Err(Error::InvalidTagLength);
    }
    u32::try_from(tag_length).map_err(|_| Error::InvalidTagLength)
}

fn prehash(parameters: Parameters, tag_length: u32, inputs: [&[u8]; 4]) -> [u8; 64] {
    // Every piece is at most u32::MAX bytes and the digest is 64 bytes.
    let mut hasher = Blake2b::new(64).expect("valid BLAKE2b output size");
    let words = [
        parameters.lanes as u32,
        tag_length,
        parameters.memory_kib,
        parameters.iterations,
        VERSION,
        VARIANT,
    ];
    for value in words {
        hasher
            .update(&value.to_le_bytes())
            .expect("bounded Argon2 inputs");
    }
    for input in inputs {
        hasher
            .update(&(input.len() as u32).to_le_bytes())
            .expect("bounded Argon2 inputs");
        hasher.update(input).expect("bounded Argon2 inputs");
    }
    let mut result = [0; 64];
    hasher
        .finalize(&mut result)
        .expect("matching BLAKE2b output size");
    result
}

fn prefixed_hash(input: &[u8], length: u32, output: &mut [u8]) {
    let mut hasher = Blake2b::new(output.len()).expect("valid BLAKE2b output size");
    hasher
        .update(&length.to_le_bytes())
        .expect("bounded H-prime input");
    hasher.update(input).expect("bounded H-prime input");
    hasher
        .finalize(output)
        .expect("matching BLAKE2b output size");
}

// RFC 9106 H'. The callers supply a 4..=u32::MAX-byte output and <=1 KiB input.
fn long_hash(input: &[u8], mut output: &mut [u8]) {
    let length = output.len() as u32;
    if output.len() <= 64 {
        prefixed_hash(input, length, output);
        return;
    }
    let mut previous = [0; 64];
    prefixed_hash(input, length, &mut previous);
    while output.len() > 64 {
        let (prefix, remaining) = output.split_at_mut(32);
        prefix.copy_from_slice(&previous[..32]);
        output = remaining;
        if output.len() > 64 {
            let mut next = [0; 64];
            digest(&previous, &mut next).expect("valid BLAKE2b output size");
            previous = next;
        }
    }
    digest(&previous, output).expect("valid final H-prime digest size");
}

#[cfg(test)]
mod tests;
