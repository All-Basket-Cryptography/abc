use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit,
};
use zeroize::Zeroizing;

use crate::{os_key, Error};

/// A transient, non-clonable sealing key with a single nonce owner.
pub struct Sealer {
    key: Zeroizing<[u8; 32]>,
    next: Option<u64>,
}

/// A decryption-only handle. It never allocates outbound nonces.
pub struct Opener(Zeroizing<[u8; 32]>);

pub struct SealedMessage {
    pub nonce: [u8; 12],
    /// Ciphertext followed by the 16-byte Poly1305 tag.
    pub ciphertext: Vec<u8>,
}

impl Sealer {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self {
            key: os_key()?,
            next: Some(0),
        })
    }

    pub fn opener(&self) -> Opener {
        Opener(self.key.clone())
    }

    pub fn seal(
        &mut self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedMessage, Error> {
        let counter = self.next.ok_or(Error::NonceExhausted)?;
        self.next = counter.checked_add(1);
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let ciphertext = seal_bytes(&self.key, &nonce, associated_data, plaintext)?;
        Ok(SealedMessage { nonce, ciphertext })
    }
}

impl Opener {
    pub fn open(&self, associated_data: &[u8], message: &SealedMessage) -> Result<Vec<u8>, Error> {
        ChaCha20Poly1305::new((&*self.0).into())
            .decrypt(
                (&message.nonce).into(),
                Payload {
                    msg: &message.ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| Error::AuthenticationFailed)
    }
}

fn seal_bytes(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::SealFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &str) -> Vec<u8> {
        bytes
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8439_section_2_8_2() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce = hex("070000004041424344454647").try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = hex(concat!(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373",
            "206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c",
            "79206f6e652074697020666f7220746865206675747572652c2073756e73637265",
            "656e20776f756c642062652069742e"
        ));
        let expected = hex(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        ));
        assert_eq!(
            seal_bytes(&key, &nonce, &aad, &plaintext).unwrap(),
            expected
        );
        let recovered = Opener(Zeroizing::new(key))
            .open(
                &aad,
                &SealedMessage {
                    nonce,
                    ciphertext: expected,
                },
            )
            .unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn authenticates_data_nonce_and_tag_and_enforces_exhaustion() {
        let mut sealer = Sealer {
            key: Zeroizing::new([7; 32]),
            next: Some(u64::MAX - 1),
        };
        let opener = sealer.opener();
        let first = sealer.seal(b"scope", b"data").unwrap();
        let mut last = sealer.seal(b"scope", b"").unwrap();
        assert_ne!(first.nonce, last.nonce);
        assert_eq!(opener.open(b"scope", &first).unwrap(), b"data");
        assert_eq!(
            opener.open(b"other", &first),
            Err(Error::AuthenticationFailed)
        );
        last.nonce[0] ^= 1;
        assert_eq!(
            opener.open(b"scope", &last),
            Err(Error::AuthenticationFailed)
        );
        last.nonce[0] ^= 1;
        last.ciphertext[0] ^= 1;
        assert_eq!(
            opener.open(b"scope", &last),
            Err(Error::AuthenticationFailed)
        );
        assert!(matches!(
            sealer.seal(b"scope", b"data"),
            Err(Error::NonceExhausted)
        ));
    }
}
