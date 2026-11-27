use abc_chacha20_poly1305::{open_in_place, seal_in_place, Error};

fn hex(encoded: &str) -> Vec<u8> {
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn rfc8439_aead_vector() {
    let key = core::array::from_fn(|i| 0x80 + i as u8);
    let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = hex(concat!(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173",
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f",
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73",
        "637265656e20776f756c642062652069742e",
    ));
    let mut data = plaintext.clone();
    let tag = seal_in_place(&key, &nonce, &aad, &mut data).unwrap();
    assert_eq!(
        data,
        hex(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
        ))
    );
    assert_eq!(tag.as_slice(), hex("1ae10b594f09e26a7e902ecbd0600691"));
    open_in_place(&key, &nonce, &aad, &mut data, &tag).unwrap();
    assert_eq!(data, plaintext);
}

#[test]
fn rejects_each_changed_tag_byte_and_preserves_ciphertext() {
    let key = [2; 32];
    for (index, size) in [0, 1, 15, 16, 17, 63, 64, 65, 273].into_iter().enumerate() {
        let mut nonce = [3; 12];
        nonce[0] = index as u8;
        let mut cipher = vec![4; size];
        let tag = seal_in_place(&key, &nonce, b"associated data", &mut cipher).unwrap();
        for i in 0..tag.len() {
            let mut tampered = tag;
            tampered[i] ^= 1;
            let mut input = cipher.clone();
            assert_eq!(
                open_in_place(&key, &nonce, b"associated data", &mut input, &tampered),
                Err(Error::AuthenticationFailed)
            );
            assert_eq!(input, cipher);
        }
        let mut input = cipher.clone();
        assert_eq!(
            open_in_place(&key, &nonce, b"wrong associated data", &mut input, &tag),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(input, cipher);
        if !input.is_empty() {
            input[0] ^= 1;
            let saved = input.clone();
            assert_eq!(
                open_in_place(&key, &nonce, b"associated data", &mut input, &tag),
                Err(Error::AuthenticationFailed)
            );
            assert_eq!(input, saved);
        }
    }
}
