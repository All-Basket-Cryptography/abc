#![forbid(unsafe_code)]
//! Experimental secret-bearing profiles built on pinned upstream primitives.

pub mod sealed_message;
pub mod wallet;

use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    EntropyUnavailable,
    NonceExhausted,
    SealFailed,
    AuthenticationFailed,
    InvalidChallenge,
    InvalidSignature,
}

fn fill_key(
    fill: impl FnOnce(&mut [u8]) -> Result<(), Error>,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut bytes = Zeroizing::new([0; 32]);
    fill(bytes.as_mut())?;
    Ok(bytes)
}

fn os_key() -> Result<Zeroizing<[u8; 32]>, Error> {
    fill_key(|output| getrandom::fill(output).map_err(|_| Error::EntropyUnavailable))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_failure_has_no_fallback() {
        let result = fill_key(|bytes| {
            bytes[0] = 1;
            Err(Error::EntropyUnavailable)
        });
        assert!(matches!(result, Err(Error::EntropyUnavailable)));
    }
}
