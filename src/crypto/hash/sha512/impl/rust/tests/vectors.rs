use abc_sha512::{digest, Sha512};

fn hex(bytes: [u8; 64]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn known_answers() {
    assert_eq!(
        hex(digest(b"").unwrap()),
        concat!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        )
    );
    assert_eq!(
        hex(digest(b"abc").unwrap()),
        concat!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )
    );
}

#[test]
fn independent_vectors_and_all_splits() {
    let data: Vec<u8> = (0..257).map(|i| (i * i + 17) as u8).collect();
    for (length, expected) in [
        (
            111,
            concat!(
                "5b1ef535465a912275ab673969f1889050deb1f78b54a764041daf9391ffc149",
                "8b0e2aae5cbdf750b18a9e77cf77708896aaefa15c95167501cc208e0e4fdddc",
            ),
        ),
        (
            112,
            concat!(
                "5ed1839fb5e66511882725571f14773c633230a8a41f8d1128310e8fd1380225",
                "66548fd32f27fe957a88eef9193096f307313dee6b9fe89f031232991e72a161",
            ),
        ),
        (
            127,
            concat!(
                "2982562800f20eb59b54b3bf22bbfc1947add6668c04171fc803d79d23de43d2",
                "2dc37b3c4127774eea4a8754a84adfab6517d6f5284b0f149a0f728c32ef56eb",
            ),
        ),
        (
            128,
            concat!(
                "4eef2cae4bfd0bc36ae63defeca21bc7ee20cf3c19bb9604e62446a79fe3cdd1",
                "e047641fa59ed08a49dcab3c9023d5b685541eba4579d0e34c2780dddb56e820",
            ),
        ),
        (
            129,
            concat!(
                "d4fa1dc1a9a33ee01815a62f3204e259e1778e2c04f91f79f5d0dc22e4f52ef1",
                "9281c826f22306da70f9be065a374060b27b90a54175bbd89c0d5cf6e3154410",
            ),
        ),
        (
            257,
            concat!(
                "001d034ceec3c0f28f97a884e267f3ac068e2c6e2b0feab8ec91f7aa66f9946e",
                "2e4d89944868b7902c4653b63f43757514decd6bfa9e3a4e004f0b40a3973e1b",
            ),
        ),
    ] {
        let input = &data[..length];
        assert_eq!(hex(digest(input).unwrap()), expected);
        for split in 0..=length {
            let mut state = Sha512::new();
            state.update(&input[..split]).unwrap();
            state.update(&[]).unwrap();
            state.update(&input[split..]).unwrap();
            assert_eq!(
                hex(state.finalize()),
                expected,
                "length {length}, split {split}"
            );
        }
    }
}
