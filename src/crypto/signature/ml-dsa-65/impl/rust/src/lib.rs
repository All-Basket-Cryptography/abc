#![forbid(unsafe_code)]

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey, VerifyingKey,
};

pub const SEED_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SIGNATURE_BYTES: usize = 3309;
pub const MAX_CONTEXT_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ContextLength,
    Signing,
}

pub fn public_key(seed: &[u8; SEED_BYTES]) -> [u8; PUBLIC_KEY_BYTES] {
    let key = SigningKey::<MlDsa65>::from_seed(&(*seed).into());
    key.verifying_key().encode().into()
}

pub fn sign(
    seed: &[u8; SEED_BYTES],
    message: &[u8],
    context: &[u8],
) -> Result<[u8; SIGNATURE_BYTES], Error> {
    if context.len() > MAX_CONTEXT_BYTES {
        return Err(Error::ContextLength);
    }
    let key = SigningKey::<MlDsa65>::from_seed(&(*seed).into());
    let signature = key
        .expanded_key()
        .sign_deterministic(message, context)
        .map_err(|_| Error::Signing)?;
    Ok(signature.encode().into())
}

pub fn verify(key: &[u8], message: &[u8], signature: &[u8], context: &[u8]) -> bool {
    if context.len() > MAX_CONTEXT_BYTES {
        return false;
    }
    let Ok(public) = EncodedVerifyingKey::<MlDsa65>::try_from(key) else {
        return false;
    };
    let Ok(encoded) = EncodedSignature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    let Some(signature) = Signature::<MlDsa65>::decode(&encoded) else {
        return false;
    };
    VerifyingKey::<MlDsa65>::decode(&public).verify_with_context(message, context, &signature)
}
