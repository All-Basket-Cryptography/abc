use abc_chacha20::{apply_keystream, CounterExhausted};

#[test]
fn rfc8439_multiblock_cipher_vector() {
    let key = core::array::from_fn(|i| i as u8);
    let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    let encoded = concat!(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173",
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f",
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73",
        "637265656e20776f756c642062652069742e",
    );
    let mut input: Vec<u8> = (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap())
        .collect();
    apply_keystream(&key, &nonce, 1, &mut input).unwrap();
    let actual: String = input.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        actual,
        concat!(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b",
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8",
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736",
            "5af90bbf74a35be6b40b8eedf2785e42874d",
        )
    );
}

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
