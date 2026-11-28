use abc_aes256::Aes256;

fn hex<const N: usize>(encoded: &str) -> [u8; N] {
    assert_eq!(encoded.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&encoded[2 * i..2 * i + 2], 16).unwrap())
}

fn check(key: [u8; 32], plaintext: [u8; 16], expected: [u8; 16]) {
    let cipher = Aes256::new(&key);
    let mut block = plaintext;
    cipher.encrypt(&mut block);
    assert_eq!(block, expected);
    cipher.decrypt(&mut block);
    assert_eq!(block, plaintext);
}

#[test]
fn known_answer_vectors() {
    check(
        core::array::from_fn(|i| i as u8),
        hex("00112233445566778899aabbccddeeff"),
        hex("8ea2b7ca516745bfeafc49904b496089"),
    );
    check(
        hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        hex("6bc1bee22e409f96e93d7e117393172a"),
        hex("f3eed1bdb5d2a03c064b5a7e3db181f8"),
    );
}
