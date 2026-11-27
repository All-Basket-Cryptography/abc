#![no_std]
#![forbid(unsafe_code)]
//! Research implementation of HMAC with the portable ABC SHA-256 core.

use abc_sha256::{digest, Sha256, DIGEST_BYTES, MAX_MESSAGE_BYTES};
use core::fmt;

const BLOCK_BYTES: usize = 64;
pub const TAG_BYTES: usize = DIGEST_BYTES;
pub const MAX_KEY_BYTES: u64 = MAX_MESSAGE_BYTES;
pub const MAX_INPUT_BYTES: u64 = MAX_MESSAGE_BYTES - BLOCK_BYTES as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HmacError {
    KeyTooLong,
    MessageTooLong,
}

impl fmt::Display for HmacError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::KeyTooLong => "HMAC key exceeds the SHA-256 message limit",
            Self::MessageTooLong => "HMAC input exceeds the available SHA-256 message length",
        })
    }
}

impl core::error::Error for HmacError {}

/// Streaming tag computation with no retained references to caller buffers.
pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    /// Use a zero-padded key block, hashing keys longer than one block first.
    pub fn new(key: &[u8]) -> Result<Self, HmacError> {
        let mut key_block = [0; BLOCK_BYTES];
        if key.len() > BLOCK_BYTES {
            let hashed = digest(key).map_err(|_| HmacError::KeyTooLong)?;
            key_block[..TAG_BYTES].copy_from_slice(&hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut inner = Sha256::new();
        let inner_pad = key_block.map(|byte| byte ^ 0x36);
        inner
            .update(&inner_pad)
            .map_err(|_| HmacError::MessageTooLong)?;

        let mut outer = Sha256::new();
        let outer_pad = key_block.map(|byte| byte ^ 0x5c);
        outer
            .update(&outer_pad)
            .map_err(|_| HmacError::MessageTooLong)?;
        Ok(Self { inner, outer })
    }

    /// Append bytes to the authenticated message. An overflow preserves the state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), HmacError> {
        self.inner
            .update(input)
            .map_err(|_| HmacError::MessageTooLong)
    }

    /// Consume this state and return the complete 32-byte tag.
    pub fn finalize(mut self) -> Result<[u8; TAG_BYTES], HmacError> {
        let inner_digest = self.inner.finalize();
        self.outer
            .update(&inner_digest)
            .map_err(|_| HmacError::MessageTooLong)?;
        Ok(self.outer.finalize())
    }
}

/// Compute the complete tag for a single message.
pub fn authenticate(key: &[u8], input: &[u8]) -> Result<[u8; TAG_BYTES], HmacError> {
    let mut state = HmacSha256::new(key)?;
    state.update(input)?;
    state.finalize()
}
