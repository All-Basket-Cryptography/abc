use abc_poly1305::{Poly1305, authenticate};

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

fn block(first: u8, rest: u8) -> [u8; 16] {
    let mut bytes = [rest; 16];
    bytes[0] = first;
    bytes
}

fn check_reduction_vector(
    number: u8,
    r: [u8; 16],
    s: [u8; 16],
    blocks: &[[u8; 16]],
    expected: [u8; 16],
) {
    let mut key = [0; 32];
    key[..16].copy_from_slice(&r);
    key[16..].copy_from_slice(&s);
    let message = blocks.as_flattened();
    assert_eq!(authenticate(&key, message), expected, "vector {number}");
    for split in 0..=message.len() {
        let mut state = Poly1305::new(&key);
        state.update(&message[..split]);
        state.update(&message[split..]);
        assert_eq!(state.finalize(), expected, "vector {number}, split {split}");
    }
}

#[test]
fn rfc8439_appendix_a3_reduction_vectors() {
    let zero = [0; 16];
    let ones = [0xff; 16];
    let one = block(1, 0);
    let two = block(2, 0);

    // RFC 8439 Appendix A.3 covers partial reduction, pad overflow, a
    // carry through all-ones data, and the two sides of the modulus threshold.
    check_reduction_vector(5, two, zero, &[ones], block(3, 0));
    check_reduction_vector(6, two, ones, &[two], block(3, 0));
    check_reduction_vector(
        7,
        one,
        zero,
        &[ones, block(0xf0, 0xff), block(17, 0)],
        block(5, 0),
    );
    check_reduction_vector(8, one, zero, &[ones, block(0xfb, 0xfe), [1; 16]], zero);
    check_reduction_vector(9, two, zero, &[block(0xfd, 0xff)], block(0xfa, 0xff));

    // Vectors 10 and 11 cover 131-bit intermediate and final values.
    let mut r = one;
    r[8] = 4;
    let first = [
        0xe3, 0x35, 0x94, 0xd7, 0x50, 0x5e, 0x43, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let second = [
        0x33, 0x94, 0xd7, 0x50, 0x5e, 0x43, 0x79, 0xcd, 1, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut tag = block(0x14, 0);
    tag[8] = 0x55;
    check_reduction_vector(10, r, zero, &[first, second, zero, one], tag);
    check_reduction_vector(11, r, zero, &[first, second, zero], block(0x13, 0));
}
