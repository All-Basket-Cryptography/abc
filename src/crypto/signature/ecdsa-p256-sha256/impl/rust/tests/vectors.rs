use abc_ecdsa_p256_sha256::{public_key, sign, verify, Error};

fn hex<const N: usize>(encoded: &str) -> [u8; N] {
    assert_eq!(encoded.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&encoded[2 * i..2 * i + 2], 16).unwrap())
}

fn test_key() -> [u8; 32] {
    hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
}

fn order() -> [u8; 32] {
    hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
}

#[test]
fn rfc6979_sha256_signatures_and_key() {
    let private = test_key();
    let public = public_key(&private).unwrap();
    assert_eq!(
        public,
        hex(concat!(
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        ))
    );
    let mut compressed = [0; 33];
    compressed[0] = 3;
    compressed[1..].copy_from_slice(&public[1..33]);
    let cases: [(&[u8], [u8; 64]); 2] = [
        (
            b"sample",
            hex(concat!(
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            )),
        ),
        (
            b"test",
            hex(concat!(
                "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
                "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            )),
        ),
    ];
    for (message, expected) in cases {
        assert_eq!(sign(&private, message), Ok(expected));
        assert_eq!(sign(&private, message), Ok(expected));
        assert_eq!(verify(&public, message, &expected), Ok(()));
        assert_eq!(verify(&compressed, message, &expected), Ok(()));
    }
    let low_s_alternative = hex(concat!(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
    ));
    assert_eq!(verify(&public, b"sample", &low_s_alternative), Ok(()));
}

#[test]
fn rejects_invalid_scalars_encodings_and_messages() {
    let private = test_key();
    let public = public_key(&private).unwrap();
    let message = b"sample";
    let signature = sign(&private, message).unwrap();
    for bad in [[0; 32], order(), [0xff; 32]] {
        assert_eq!(public_key(&bad), Err(Error::InvalidPrivateKey));
        assert_eq!(sign(&bad, message), Err(Error::InvalidPrivateKey));
    }
    let mut hybrid = public;
    hybrid[0] = 7;
    let mut off_curve = [0; 65];
    off_curve[0] = 4;
    let mut noncanonical = [0xff; 33];
    noncanonical[0] = 2;
    for bad in [
        &[][..],
        &[0],
        &public[..64],
        &hybrid,
        &off_curve,
        &noncanonical,
    ] {
        assert_eq!(
            verify(bad, message, &signature),
            Err(Error::InvalidPublicKey)
        );
    }
    for offset in [0, 32] {
        for bad in [[0; 32], order()] {
            let mut corrupted = signature;
            corrupted[offset..offset + 32].copy_from_slice(&bad);
            assert_eq!(
                verify(&public, message, &corrupted),
                Err(Error::InvalidSignature)
            );
        }
    }
    let mut other_key = [0; 32];
    other_key[31] = 1;
    let mut changed = signature;
    changed[0] ^= 1;
    assert_eq!(
        verify(&public, message, &changed),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        verify(&public, b"test", &signature),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        verify(&public_key(&other_key).unwrap(), message, &signature),
        Err(Error::VerificationFailed),
    );
}
