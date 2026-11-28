use abc_scrypt::{derive, Parameters};
use std::io::{self, BufRead};

fn decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let parts: Vec<_> = line.split(':').collect();
        let [password, salt, n, r, p, len] = parts.as_slice() else {
            panic!("invalid conformance case");
        };
        let params =
            Parameters::new(n.parse().unwrap(), r.parse().unwrap(), p.parse().unwrap()).unwrap();
        let mut out = vec![0; len.parse().unwrap()];
        let mut work = vec![0; params.workspace_size()];
        derive(
            &decode(password),
            &decode(salt),
            params,
            &mut out,
            &mut work,
        )
        .unwrap();
        for byte in out {
            print!("{byte:02x}");
        }
        println!();
    }
}
