#![forbid(unsafe_code)]

use ml_kem::B32;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use zeroize::Zeroizing;

pub const SEED_BYTES: usize = 64;
pub const PUBLIC_KEY_BYTES: usize = 1184;
pub const CIPHERTEXT_BYTES: usize = 1088;
pub const SHARED_SECRET_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    PublicKey,
    CiphertextLength,
    Entropy,
}

pub fn public_key(seed: &[u8; SEED_BYTES]) -> [u8; PUBLIC_KEY_BYTES] {
    let key = DecapsulationKey::from_seed((*seed).into());
    key.encapsulation_key().to_bytes().into()
}

pub fn encapsulate(
    encoded: &[u8; PUBLIC_KEY_BYTES],
) -> Result<([u8; CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES]), Error> {
    let key = EncapsulationKey::new(&(*encoded).into()).map_err(|_| Error::PublicKey)?;
    let mut randomness = Zeroizing::new(B32::default());
    getrandom::fill(randomness.as_mut_slice()).map_err(|_| Error::Entropy)?;
    let (ciphertext, shared) = key.encapsulate_deterministic(&randomness);
    Ok((ciphertext.into(), shared.into()))
}

/// A correctly sized invalid ciphertext follows the provider's implicit rejection.
pub fn decapsulate(
    seed: &[u8; SEED_BYTES],
    ciphertext: &[u8],
) -> Result<[u8; SHARED_SECRET_BYTES], Error> {
    let wire = Ciphertext::try_from(ciphertext).map_err(|_| Error::CiphertextLength)?;
    let key = DecapsulationKey::from_seed((*seed).into());
    Ok(key.decapsulate(&wire).into())
}
