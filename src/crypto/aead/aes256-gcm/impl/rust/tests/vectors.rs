use abc_aes256_gcm::{open_in_place, seal_in_place, Error};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn nist_partial_blocks_and_aad() {
    let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        .try_into()
        .unwrap();
    let nonce = hex("cafebabefacedbaddecaf888").try_into().unwrap();
    let aad = hex("3ad77bb40d7a3660a89ecaf32466ef97f5d3d585");
    let plaintext = hex(concat!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    ));
    let mut data = plaintext.clone();
    let tag = seal_in_place(&key, &nonce, &aad, &mut data).unwrap();
    assert_eq!(
        data,
        hex(concat!(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        ))
    );
    assert_eq!(tag.as_slice(), hex("e097195f4532da895fb917a5a55c6aa0"));
    for bit in 0..tag.len() * u8::BITS as usize {
        let mut changed = tag;
        changed[bit / 8] ^= 1 << (bit % 8);
        let mut preserved = data.clone();
        assert_eq!(
            open_in_place(&key, &nonce, &aad, &mut preserved, &changed),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(preserved, data);
    }
    let mut preserved = data.clone();
    assert_eq!(
        open_in_place(&key, &nonce, &[], &mut preserved, &tag),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(preserved, data);
    open_in_place(&key, &nonce, &aad, &mut data, &tag).unwrap();
    assert_eq!(data, plaintext);
}

#[test]
fn empty_payload_known_tag() {
    let tag = seal_in_place(&[0; 32], &[0; 12], b"", &mut []).unwrap();
    assert_eq!(tag.as_slice(), hex("530f8afbc74536b9a963b4f1c4cb738b"));
    assert_eq!(
        open_in_place(&[0; 32], &[0; 12], b"", &mut [], &tag),
        Ok(())
    );
}
