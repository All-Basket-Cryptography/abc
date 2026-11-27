use abc_poly1305::{authenticate, Poly1305};

#[test]
fn rfc8439_known_answer_for_every_split() {
    let key = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    let message = b"Cryptographic Forum Research Group";
    let expected = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ];
    assert_eq!(authenticate(&key, message), expected);
    for split in 0..=message.len() {
        let mut state = Poly1305::new(&key);
        state.update(&message[..split]);
        state.update(&[]);
        state.update(&message[split..]);
        assert_eq!(state.finalize(), expected);
    }
}

#[test]
fn empty_message_and_zero_multiplier() {
    let mut key = [0; 32];
    key[16..].copy_from_slice(&[0xab; 16]);
    assert_eq!(authenticate(&key, b""), [0xab; 16]);
    assert_eq!(authenticate(&key, &[0xff; 257]), [0xab; 16]);
}
