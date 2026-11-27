use abc_sha256::{digest, Sha256};

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn check(input: &[u8], expected: &str) {
    assert_eq!(hex(digest(input).unwrap()), expected);
    for split in 0..=input.len() {
        let mut context = Sha256::new();
        context.update(&input[..split]).unwrap();
        context.update(&[]).unwrap();
        context.update(&input[split..]).unwrap();
        assert_eq!(hex(context.finalize()), expected, "split at {split}");
    }
}

#[test]
fn nist_examples() {
    // NIST Cryptographic Standards and Guidelines, SHA256.pdf, pp. 1 and 4.
    check(
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    check(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
}

#[test]
fn padding_boundaries() {
    // Independent Python hashlib SHA-256, OpenSSL 3.0.21.
    let cases = [
        (
            0,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            55,
            "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
        ),
        (
            56,
            "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
        ),
        (
            63,
            "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488",
        ),
        (
            64,
            "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
        ),
        (
            65,
            "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781",
        ),
        (
            119,
            "da18797ed7c3a777f0847f429724a2d8cd5138e6ed2895c3fa1a6d39d18f7ec6",
        ),
        (
            120,
            "f52b23db1fbb6ded89ef42a23ce0c8922c45f25c50b568a93bf1c075420bbb7c",
        ),
    ];
    for (length, expected) in cases {
        let input: Vec<u8> = (0..length).map(|x| (x % 251) as u8).collect();
        check(&input, expected);
    }
}
