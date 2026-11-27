use abc_chacha20::{apply_keystream, CounterExhausted};

#[test]
fn rfc8439_block_vector() {
    let key = core::array::from_fn(|i| i as u8);
    let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    let mut output = [0; 64];
    apply_keystream(&key, &nonce, 1, &mut output).unwrap();
    let actual: String = output.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        actual,
        concat!(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e",
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        )
    );
}

#[test]
fn final_counter_and_rejection() {
    let key = [0x27; 32];
    let nonce = [0x48; 12];
    let mut message = [0xa6; 65];
    assert_eq!(
        apply_keystream(&key, &nonce, u32::MAX, &mut message),
        Err(CounterExhausted)
    );
    assert_eq!(message, [0xa6; 65]);
    apply_keystream(&key, &nonce, u32::MAX, &mut []).unwrap();
    apply_keystream(&key, &nonce, u32::MAX, &mut message[..64]).unwrap();
    assert_ne!(message, [0xa6; 65]);
    apply_keystream(&key, &nonce, u32::MAX, &mut message[..64]).unwrap();
    assert_eq!(message, [0xa6; 65]);
}

#[test]
fn aligned_split_uses_next_counter() {
    let key = [0x11; 32];
    let nonce = [0x2a; 12];
    let mut whole = [0xa6; 257];
    let mut split = whole;
    apply_keystream(&key, &nonce, 31, &mut whole).unwrap();
    apply_keystream(&key, &nonce, 31, &mut split[..192]).unwrap();
    apply_keystream(&key, &nonce, 34, &mut split[192..]).unwrap();
    assert_eq!(whole, split);
}
