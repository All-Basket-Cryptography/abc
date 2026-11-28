use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{os_key, Error};

const DOMAIN: &[u8] = b"ABC-WALLET-CHALLENGE-V1\0";
const MAX_OPERATION_BYTES: usize = 1_048_576;

/// An application-scoped challenge. The application owns nonce freshness and replay storage.
pub struct Challenge<'a> {
    pub audience: &'a str,
    pub nonce: [u8; 32],
    pub operation: &'a [u8],
}

impl Challenge<'_> {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let audience = self.audience.as_bytes();
        if audience.is_empty()
            || audience.len() > 253
            || self.operation.len() > MAX_OPERATION_BYTES
            || self.audience.split('.').any(|part| {
                part.is_empty()
                    || part.starts_with('-')
                    || part.ends_with('-')
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(Error::InvalidChallenge);
        }
        let mut bytes =
            Vec::with_capacity(DOMAIN.len() + 37 + audience.len() + self.operation.len());
        bytes.extend(DOMAIN);
        bytes.push(audience.len() as u8);
        bytes.extend(audience);
        bytes.extend(self.nonce);
        bytes.extend((self.operation.len() as u32).to_be_bytes());
        bytes.extend(self.operation);
        Ok(bytes)
    }
}

pub struct WalletSigner(SigningKey);

impl WalletSigner {
    pub fn generate() -> Result<Self, Error> {
        let seed = os_key()?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    /// Import a dedicated Ed25519 seed. The caller retains ownership of its source buffer.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, challenge: &Challenge<'_>) -> Result<[u8; 64], Error> {
        Ok(self.0.sign(&challenge.encode()?).to_bytes())
    }
}

pub fn verify(
    public_key: &[u8; 32],
    challenge: &Challenge<'_>,
    signature: &[u8; 64],
) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidSignature)?;
    key.verify_strict(&challenge.encode()?, &Signature::from_bytes(signature))
        .map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_canonical_audience_nonce_and_operation() {
        let signer = WalletSigner::from_seed(&[42; 32]);
        let public_key = signer.public_key();
        let challenge = Challenge {
            audience: "wallet.example",
            nonce: [1; 32],
            operation: b"sign-in",
        };
        let mut signature = signer.sign(&challenge).unwrap();
        assert_eq!(verify(&public_key, &challenge, &signature), Ok(()));
        for other in [
            Challenge {
                audience: "other.example",
                ..challenge
            },
            Challenge {
                nonce: [2; 32],
                ..challenge
            },
            Challenge {
                operation: b"withdraw",
                ..challenge
            },
        ] {
            assert_eq!(
                verify(&public_key, &other, &signature),
                Err(Error::InvalidSignature)
            );
        }
        assert_eq!(
            signer.sign(&Challenge {
                audience: "Wallet.Example",
                ..challenge
            }),
            Err(Error::InvalidChallenge)
        );
        assert_eq!(
            verify(&[0; 32], &challenge, &signature),
            Err(Error::InvalidSignature)
        );
        signature[0] ^= 1;
        assert_eq!(
            verify(&public_key, &challenge, &signature),
            Err(Error::InvalidSignature)
        );
    }
}
