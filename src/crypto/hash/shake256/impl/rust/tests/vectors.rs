use abc_shake256::{xof, Shake256};

#[test]
fn known_outputs() {
    for (input, expected) in [
        (
            &b""[..],
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
        ),
        (
            &b"abc"[..],
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
        ),
    ] {
        let mut output = [0; 32];
        xof(input, &mut output);
        assert_eq!(
            output
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            expected
        );
    }
}

#[test]
fn independently_computed_late_output() {
    let input: Vec<u8> = (0..137).collect();
    let mut output = [0; 300];
    xof(&input, &mut output);
    let actual: String = output[268..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        actual,
        "96aec260c660fb61a2c4e10a262ffa559292139c76cdbda6cd0a2754dfccd964"
    );
}

#[test]
fn rate_and_chunk_boundaries() {
    for length in [0, 1, 135, 136, 137, 271, 272, 273, 1000] {
        let input: Vec<u8> = (0..length).map(|index| index as u8).collect();
        let mut expected = [0; 409];
        xof(&input, &mut expected);
        for split in 0..=length {
            let mut state = Shake256::new();
            state.update(&input[..split]);
            state.update(&[]);
            state.update(&input[split..]);
            let mut reader = state.finalize();
            let mut output = [0; 409];
            let mut remaining = &mut output[..];
            for count in [0, 1, 134, 1, 136, 137] {
                let (target, rest) = remaining.split_at_mut(count);
                reader.read(target);
                remaining = rest;
            }
            assert_eq!(output, expected, "input length {length}, split {split}");
        }
    }
}
