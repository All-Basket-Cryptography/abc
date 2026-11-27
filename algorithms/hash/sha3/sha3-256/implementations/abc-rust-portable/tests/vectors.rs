use abc_sha3_256::digest;

fn hex_digest(message: &[u8]) -> String {
    digest(message)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn nist_byte_aligned_examples() {
    assert_eq!(
        hex_digest(b""),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
    assert_eq!(
        hex_digest(&[0xa3; 200]),
        "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"
    );
}

#[test]
fn fips_202_domain_separator() {
    // The SHA3-256 and Keccak-256 digests of "abc" differ.
    assert_eq!(
        hex_digest(b"abc"),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    assert_ne!(
        hex_digest(b"abc"),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
}

#[test]
fn independently_computed_rate_boundaries() {
    let vectors = [
        (
            135,
            "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2",
        ),
        (
            136,
            "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5",
        ),
        (
            137,
            "ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca",
        ),
        (
            271,
            "0153fcdb6825d836b10835ccb3999dc1d8b68492f77e7e38afa31f8e244bd7af",
        ),
        (
            272,
            "b7ccd55b6c2c3fa144c9e0624059294975a348b02f321abe289701d3012f7794",
        ),
        (
            273,
            "4827800416bd25b01f53360454943ef688112eaee40422929a59af596a2c0be7",
        ),
        (
            1024,
            "ba7f1834cddbba9f82cd4dcf7a106bb2e615fec90020f5a5de8efff8d49198b6",
        ),
    ];
    for (length, expected) in vectors {
        let input: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        assert_eq!(hex_digest(&input), expected, "input length {length}");
    }
}
