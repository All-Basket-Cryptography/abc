use super::*;

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap())
}

#[test]
fn rfc_9106_argon2id_vector() {
    let parameters = Parameters::new(32, 3, 4).unwrap();
    let inputs: [&[u8]; 4] = [&[1; 32], &[2; 16], &[3; 8], &[4; 12]];
    let mut workspace = [[0x9876; BLOCK_WORDS]; 33];
    let h0 = prehash(parameters, 32, inputs);
    assert_eq!(
        h0,
        hex(concat!(
            "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b854",
            "6a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997"
        ))
    );

    let expected = [
        (
            [
                0x6b2e09f10671bd43,
                0xf69f5c27918a21be,
                0xdea7810ea41290e1,
                0x6787f7171870f893,
            ],
            [
                0x377fa81666dc7f2b,
                0x50e586398a9c39c8,
                0x6f732732a550924a,
                0x81f88b28683ea8e5,
            ],
        ),
        (
            [
                0x3653ec9d01583df9,
                0x69ef53a72d1e1fd3,
                0x35635631744ab54f,
                0x599512e96a37ab6e,
            ],
            [
                0x4d4b435cea35caa6,
                0xc582210d99ad1359,
                0xd087971b36fd6d77,
                0xa55222a93754c692,
            ],
        ),
        (
            [
                0x942363968ce597a4,
                0xa22448c0bdad5760,
                0xa5f80662b6fa8748,
                0xa0f9b9ce392f719f,
            ],
            [
                0xd723359b485f509b,
                0xcb78824f42375111,
                0x35bc8cc6e83b1875,
                0x0b012846a40f346a,
            ],
        ),
    ];
    let active = &mut workspace[..parameters.workspace_blocks()];
    matrix::initialize(active, parameters, &h0);
    for (pass, (start, end)) in expected.into_iter().enumerate() {
        matrix::fill_pass(active, parameters, pass as u32);
        assert_eq!(active[0][..4], start, "first block after pass {pass}");
        assert_eq!(active[31][124..], end, "last block after pass {pass}");
    }

    // Rerun through the public entry point on dirty workspace.
    let mut output = [0; 32];
    derive(
        inputs[0],
        inputs[1],
        inputs[2],
        inputs[3],
        parameters,
        &mut output,
        &mut workspace,
    )
    .unwrap();
    assert_eq!(
        output,
        hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
    assert_eq!(workspace[32], [0x9876; BLOCK_WORDS]);
}

#[test]
fn parameter_domain_and_rounding() {
    for (memory, iterations, lanes) in [
        (8, 1, 0),
        (8, 0, 1),
        (15, 1, 2),
        (u32::MAX, u32::MAX, u32::MAX),
        (u32::MAX, 1, MAX_LANES + 1),
    ] {
        assert_eq!(
            Parameters::new(memory, iterations, lanes),
            Err(Error::InvalidParameters)
        );
    }
    assert_eq!(Parameters::new(31, 2, 3).unwrap().workspace_blocks(), 24);
    assert_eq!(Parameters::new(8, 1, 1).unwrap().workspace_blocks(), 8);
    let max_memory = Parameters::new(u32::MAX, 1, 1);
    match usize::BITS {
        64 => assert_eq!(
            max_memory.unwrap().workspace_blocks(),
            (u32::MAX - 3) as usize
        ),
        32 => assert_eq!(max_memory, Err(Error::WorkspaceSize)),
        _ => {}
    }
}

#[test]
fn length_encoding_limits() {
    assert_eq!(validate_lengths([0, 8, 0, 0], 4), Ok(4));
    assert_eq!(validate_lengths([0, 7, 0, 0], 4), Err(Error::SaltTooShort));
    assert_eq!(
        validate_lengths([0, 8, 0, 0], 3),
        Err(Error::InvalidTagLength)
    );
    if let Ok(too_long) = usize::try_from(u64::from(u32::MAX) + 1) {
        for index in 0..4 {
            let mut lengths = [1, 8, 1, 1];
            lengths[index] = too_long;
            assert_eq!(validate_lengths(lengths, 4), Err(Error::InputTooLong));
        }
        assert_eq!(
            validate_lengths([0, 8, 0, 0], too_long),
            Err(Error::InvalidTagLength)
        );
        assert_eq!(
            validate_lengths([u32::MAX as usize; 4], u32::MAX as usize),
            Ok(u32::MAX)
        );
    }
}

#[test]
fn rejected_inputs_leave_both_buffers_unchanged() {
    let parameters = Parameters::new(8, 1, 1).unwrap();
    let mut output = [0xa5; 4];
    let sentinel = [0x5a; BLOCK_WORDS];
    let mut workspace = [sentinel; 8];
    let salt = b"12345678";
    assert_eq!(
        derive(
            b"password",
            salt,
            b"",
            b"",
            parameters,
            &mut output,
            &mut workspace[..7]
        ),
        Err(Error::WorkspaceTooSmall)
    );
    assert_eq!(
        derive(
            b"password",
            &salt[..7],
            b"",
            b"",
            parameters,
            &mut output,
            &mut workspace
        ),
        Err(Error::SaltTooShort)
    );
    assert_eq!(
        derive(
            b"password",
            salt,
            b"",
            b"",
            parameters,
            &mut output[..3],
            &mut workspace
        ),
        Err(Error::InvalidTagLength)
    );
    assert_eq!(output, [0xa5; 4]);
    assert_eq!(workspace, [sentinel; 8]);
}
