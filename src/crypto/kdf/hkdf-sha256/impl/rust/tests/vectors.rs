use abc_hkdf_sha256::{derive, expand, extract, HkdfError, MAX_OUTPUT_BYTES, PRK_BYTES};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut hex, byte| {
        write!(&mut hex, "{byte:02x}").unwrap();
        hex
    })
}

fn verify_vector(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    expected_prk: &str,
    expected_output: &str,
) {
    let prk = extract(salt, ikm).unwrap();
    assert_eq!(hex(prk.as_bytes()), expected_prk);
    let mut output = vec![0; expected_output.len() / 2];
    prk.expand(info, &mut output).unwrap();
    assert_eq!(hex(&output), expected_output);
    output.fill(0);
    derive(salt, ikm, info, &mut output).unwrap();
    assert_eq!(hex(&output), expected_output);
}

#[test]
fn rfc5869_case_1() {
    let salt: Vec<u8> = (0x00..=0x0c).collect();
    let info: Vec<u8> = (0xf0..=0xf9).collect();
    verify_vector(
        &[0x0b; 22],
        Some(&salt),
        &info,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
}

#[test]
fn rfc5869_case_2() {
    let ikm: Vec<u8> = (0x00..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();
    verify_vector(
        &ikm,
        Some(&salt),
        &info,
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        concat!(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
            "cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
    );
}

#[test]
fn rfc5869_case_3() {
    for salt in [Some([].as_slice()), None] {
        verify_vector(
            &[0x0b; 22],
            salt,
            &[],
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
    }
}

#[test]
fn counter_and_output_boundaries() {
    let info = b"ABC boundary test";
    let mut output = [0xff; MAX_OUTPUT_BYTES];

    // RFC 5869 section 2.3 evaluated independently with Python hmac.digest.
    let examples = [
        (
            32,
            "de6a65d79a38fb6060533a00c96120f11c77f5d99c52f4b23f6883d5a805c235",
            "e0bb99388176ebb71ae6531c15b1beb0a27029000c12e8cfd16fbc470904c87d",
        ),
        (
            65,
            "486f8018cac7a6c9d209f71a5d6e0841512f625b30098438ff1e32cd32378b31",
            "305384159f4d535103d1c4f4da5884fcbec69025c5e3274b2942936046af3881",
        ),
    ];
    assert_eq!(MAX_OUTPUT_BYTES, 8160);
    for (key_length, first, last) in examples {
        let key: Vec<u8> = (0..key_length).collect();
        expand(&key, info, &mut output).unwrap();
        assert_eq!(hex(&output[..PRK_BYTES]), first);
        assert_eq!(hex(&output[MAX_OUTPUT_BYTES - PRK_BYTES..]), last);
        for length in [0, 1, 31, 32, 33, 8159] {
            let mut shorter = vec![0xff; length];
            expand(&key, info, &mut shorter).unwrap();
            assert_eq!(shorter, output[..length]);
        }
    }
}

#[test]
fn length_errors_preserve_output() {
    let mut output = [0x5a; MAX_OUTPUT_BYTES + 1];
    let key = [0; PRK_BYTES];
    assert_eq!(
        expand(&key, &[], &mut output),
        Err(HkdfError::OutputTooLong)
    );
    assert_eq!(output, [0x5a; MAX_OUTPUT_BYTES + 1]);
    assert_eq!(
        expand(&key[..PRK_BYTES - 1], &[], &mut output[..16]),
        Err(HkdfError::PrkTooShort)
    );
    assert_eq!(output, [0x5a; MAX_OUTPUT_BYTES + 1]);
}
