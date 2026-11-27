use abc_pbkdf2_hmac_sha256::{derive, Error};
use core::num::NonZeroU32;

fn check(password: &[u8], salt: &[u8], rounds: u32, expected: &str) {
    let mut output = vec![0xaa; expected.len() / 2];
    derive(
        password,
        salt,
        NonZeroU32::new(rounds).unwrap(),
        &mut output,
    )
    .unwrap();
    let actual: String = output.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(actual, expected);
}

#[test]
fn rfc7914_pbkdf2_vectors() {
    check(
        b"passwd",
        b"salt",
        1,
        concat!(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        ),
    );
    check(
        b"Password",
        b"NaCl",
        80_000,
        concat!(
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56",
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
        ),
    );
}

#[test]
fn long_password_prehash_matches_independent_oracle() {
    let password: Vec<u8> = (0..4096).map(|i| (i * 31 + 11) as u8).collect();
    check(
        &password,
        b"public-benchmark",
        125,
        concat!(
            "7faa3b1cf4a111eedcbf263ae25190941351df8e1d11ba0145ee175da00ce750bd",
            "23b229dcae6645cbc15187dbc2e32c72f92cb3fafcf4f78c5c2ab6f41d9029bf5",
            "2c9048e24ecb8a0",
        ),
    );
}

#[test]
fn arbitrary_prefix_and_zero_output() {
    let rounds = NonZeroU32::new(2).unwrap();
    let mut full = [0; 96];
    derive(b"p\0", b"s\0", rounds, &mut full).unwrap();
    for length in [1, 31, 32, 33, 63, 64, 65, 95] {
        let mut output = vec![0xaa; length];
        derive(b"p\0", b"s\0", rounds, &mut output).unwrap();
        assert_eq!(output, full[..length]);
    }
    let mut untouched = [0xaa];
    assert_eq!(
        derive(b"", b"", rounds, &mut untouched[..0]),
        Err(Error::OutputLength)
    );
    assert_eq!(untouched, [0xaa]);
}
