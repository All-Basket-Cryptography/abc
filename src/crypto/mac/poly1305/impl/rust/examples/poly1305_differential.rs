use abc_poly1305::{authenticate, Poly1305};
use std::io::{self, BufRead};

fn decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (key, input) = line.split_once(':').unwrap();
        let key = decode(key).try_into().unwrap();
        let input = decode(input);
        let direct = authenticate(&key, &input);
        let mut streamed = Poly1305::new(&key);
        for chunk in input.chunks(11) {
            streamed.update(chunk);
        }
        assert_eq!(streamed.finalize(), direct);
        for byte in direct {
            print!("{byte:02x}");
        }
        println!();
    }
}
