use abc_argon2id::{derive, Parameters, BLOCK_WORDS};
use std::io::{self, BufRead};

fn decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split(':').collect();
        let [memory, passes, lanes, length, password, salt, secret, data] = fields.as_slice()
        else {
            panic!("invalid differential fixture");
        };
        let parameters = Parameters::new(
            memory.parse().unwrap(),
            passes.parse().unwrap(),
            lanes.parse().unwrap(),
        )
        .unwrap();
        let mut workspace = vec![[0xa500; BLOCK_WORDS]; parameters.workspace_blocks()];
        let mut tag = vec![0; length.parse().unwrap()];
        derive(
            &decode(password),
            &decode(salt),
            &decode(secret),
            &decode(data),
            parameters,
            &mut tag,
            &mut workspace,
        )
        .unwrap();
        for byte in tag {
            print!("{byte:02x}");
        }
        println!();
    }
}
