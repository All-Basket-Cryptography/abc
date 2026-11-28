use abc_hmac_sha256::{authenticate, HmacSha256};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut hex, byte| {
        write!(&mut hex, "{byte:02x}").unwrap();
        hex
    })
}

#[test]
fn rfc4231_vectors() {
    // RFC 4231, sections 4.2, 4.3, and 4.7.
    let vectors: &[(&[u8], &[u8], &str)] = &[
        (
            &[0x0b; 20],
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
    ];
    for (key, message, expected) in vectors {
        assert_eq!(hex(&authenticate(key, message).unwrap()), *expected);
        let mut streaming = HmacSha256::new(key).unwrap();
        streaming.update(&[]).unwrap();
        for chunk in message.chunks(7) {
            streaming.update(chunk).unwrap();
        }
        assert_eq!(hex(&streaming.finalize().unwrap()), *expected);
    }
}

#[test]
fn key_block_boundaries() {
    // Independent outputs from Python 3 hmac.digest.
    let vectors = [
        (
            0,
            "10431b47fc949f227e5044e613b99a74c30050c2f1060ac90d6c7a7aef1dcc3d",
        ),
        (
            63,
            "a8305c731ed47bbe83ae3b804143b548d1dd6e4047bb0311156269e26c73b9bc",
        ),
        (
            64,
            "bb6d23930dfa5b1265e56ba176cd7f1058683849dfdd89210f32a0a2c561336b",
        ),
        (
            65,
            "019eefd56af66374fddffb7b7a6e14dd5be2798c4885bc768677ff1de5b9bb4b",
        ),
    ];
    for (length, expected) in vectors {
        let key: Vec<u8> = (0..length).collect();
        let tag = authenticate(&key, b"boundary check").unwrap();
        assert_eq!(hex(&tag), expected, "key length {length}");
    }
    assert_eq!(
        hex(&authenticate(&[], &[]).unwrap()),
        "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
    );
}
#[cfg(feature = "prepared-key")]
#[test]
fn fork_copies_both_key_states_and_the_partial_message() {
    let key = [0xd2; 131];
    let prefix = b"shared HMAC prefix";
    let mut prefix_state = abc_hmac_sha256::HmacSha256::new(&key).unwrap();
    prefix_state.update(prefix).unwrap();
    for suffix in [&b""[..], &[0x5a; 64], b"independent bytes"] {
        let mut branch = prefix_state.fork();
        branch.update(suffix).unwrap();
        let message = [&prefix[..], suffix].concat();
        let expected = abc_hmac_sha256::authenticate(&key, &message).unwrap();
        assert_eq!(branch.finalize().unwrap(), expected);
    }
    assert_eq!(
        prefix_state.finalize().unwrap(),
        abc_hmac_sha256::authenticate(&key, prefix).unwrap(),
    );
}
