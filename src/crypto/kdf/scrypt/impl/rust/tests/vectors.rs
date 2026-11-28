use abc_scrypt::{derive, Error, Parameters};

fn check(password: &[u8], salt: &[u8], n: usize, r: usize, p: usize, expected: &str) {
    let parameters = Parameters::new(n, r, p).unwrap();
    let mut work = vec![0x5a; parameters.workspace_size() + 5];
    let mut key = vec![0; expected.len() / 2];
    derive(password, salt, parameters, &mut key, &mut work).unwrap();
    assert_eq!(
        key.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        expected
    );
    assert_eq!(&work[parameters.workspace_size()..], &[0x5a; 5]);
}

#[test]
fn rfc7914_outputs() {
    check(
        b"",
        b"",
        16,
        1,
        1,
        concat!(
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442",
            "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
        ),
    );
    check(
        b"password",
        b"NaCl",
        1024,
        8,
        16,
        concat!(
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162",
            "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
        ),
    );
}

#[test]
fn invalid_inputs_preserve_output() {
    let impossible_cost = 1usize << (usize::BITS - 10);
    assert!(matches!(
        Parameters::new(impossible_cost, 4, 1),
        Err(Error::MemorySize)
    ));
    assert!(matches!(
        Parameters::new(1, 1, 1),
        Err(Error::InvalidParameters)
    ));
    assert!(matches!(
        Parameters::new(3, 1, 1),
        Err(Error::InvalidParameters)
    ));
    assert!(matches!(
        Parameters::new(1 << 16, 1, 1),
        Err(Error::InvalidParameters)
    ));
    assert!(matches!(
        Parameters::new(2, 1, 0),
        Err(Error::InvalidParameters)
    ));
    assert!(matches!(
        Parameters::new(2, usize::MAX, 1),
        Err(Error::MemorySize)
    ));
    let mut output = [0x5a; 32];
    let mut tiny = [0x11; 32];
    let parameters = Parameters::new(16, 1, 1).unwrap();
    assert_eq!(
        derive(b"password", b"salt", parameters, &mut output, &mut tiny),
        Err(Error::WorkspaceTooSmall)
    );
    assert_eq!(output, [0x5a; 32]);
    assert_eq!(tiny, [0x11; 32]);
}
