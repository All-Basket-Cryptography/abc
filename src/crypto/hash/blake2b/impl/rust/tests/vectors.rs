use abc_blake2b::{digest, Blake2b, Error};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn rfc_example_and_size_binding() {
    let mut full = [0; 64];
    digest(b"abc", &mut full).unwrap();
    assert_eq!(
        hex(&full),
        concat!(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d",
            "87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        )
    );
    let mut short = [0; 32];
    digest(b"abc", &mut short).unwrap();
    assert_ne!(short, full[..32]);
    assert!(matches!(Blake2b::new(0), Err(Error::InvalidDigestLength)));
    assert!(matches!(Blake2b::new(65), Err(Error::InvalidDigestLength)));
    let mut invalid = [0xa5; 65];
    assert_eq!(
        digest(b"abc", &mut invalid),
        Err(Error::InvalidDigestLength)
    );
    assert_eq!(invalid, [0xa5; 65]);
}

#[test]
fn final_blocks_and_all_two_chunk_splits() {
    // Byte pattern and expected digests cross-checked with Python hashlib.blake2b.
    for (length, expected) in [
        (
            0,
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        ),
        (
            127,
            "2bafc551fac2b7471a310590f926931e76efa61773f721c11a58795c861fbe01",
        ),
        (
            128,
            "d8964bd9acf62d8064e4569331ca8474ac23c1cc1a4ace160880bcea85b837f9",
        ),
        (
            129,
            "52d53b85c007796f8cc02865bd710c6bea2e1e19ddb7aef99fbbd48b87393f22",
        ),
        (
            255,
            "748a4aa0dc8cb47c53c4f5c91aed59ee63ff1b5b4864f88beed92f3fdd593aa3",
        ),
        (
            256,
            "781150a9570dd6a6086e11b0f60bb629707d99523fb8da9985403a28c6864a9d",
        ),
        (
            257,
            "7efdee97778ed5d97ea9ccd7835289e0d92a27a6ce1d3da32cbaed8369cc7099",
        ),
    ] {
        let input: Vec<_> = (0..length).map(|i| (37 * i + 11) as u8).collect();
        for split in 0..=length {
            let mut ctx = Blake2b::new(32).unwrap();
            ctx.update(&input[..split]).unwrap();
            ctx.update(b"").unwrap();
            ctx.update(&input[split..]).unwrap();
            let mut out = [0; 32];
            ctx.finalize(&mut out).unwrap();
            assert_eq!(hex(&out), expected, "length {length}, split {split}");
        }
    }
}

#[test]
fn snapshot_errors_preserve_buffer_and_context() {
    let mut ctx = Blake2b::new(31).unwrap();
    ctx.update(&[0x73; 128]).unwrap();
    let mut short = [0xa5; 30];
    assert_eq!(ctx.finalize(&mut short), Err(Error::OutputLengthMismatch));
    assert_eq!(short, [0xa5; 30]);
    let mut first = [0; 31];
    let mut second = [0; 31];
    ctx.finalize(&mut first).unwrap();
    ctx.finalize(&mut second).unwrap();
    assert_eq!(first, second);
    ctx.update(&[0x73]).unwrap();
    ctx.finalize(&mut second).unwrap();
    digest(&[0x73; 129], &mut first).unwrap();
    assert_eq!(first, second);
}
