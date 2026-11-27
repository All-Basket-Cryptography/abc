use std::hint::black_box;
use std::io::{self, BufRead};
use std::time::Instant;

const AES: &str = "aes-256-gcm";
const CHACHA: &str = "chacha20-poly1305";

fn decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

fn seal(name: &str, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
    match name {
        AES => abc_aes256_gcm::seal_in_place(key, nonce, aad, data).unwrap(),
        CHACHA => abc_chacha20_poly1305::seal_in_place(key, nonce, aad, data).unwrap(),
        _ => panic!("unknown method"),
    }
}

fn open(name: &str, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) {
    match name {
        AES => abc_aes256_gcm::open_in_place(key, nonce, aad, data, tag).unwrap(),
        CHACHA => abc_chacha20_poly1305::open_in_place(key, nonce, aad, data, tag).unwrap(),
        _ => panic!("unknown method"),
    }
}

fn benchmark() {
    let key = [0; 32];
    let aad = [0; 16];
    let mut nonce = [0; 12];
    let mut counter = 0u32;
    for name in [AES, CHACHA] {
        for length in [64, 4096] {
            let plain = vec![0x43; length];
            let mut buffer = plain.clone();
            let mut samples = [0; 9];
            for trial in 0..=samples.len() {
                let start = Instant::now();
                for _ in 0..64 {
                    counter += 1;
                    nonce[8..].copy_from_slice(&counter.to_be_bytes());
                    buffer.copy_from_slice(&plain);
                    black_box(seal(name, &key, &nonce, &aad, black_box(&mut buffer)));
                }
                if trial > 0 {
                    samples[trial - 1] = start.elapsed().as_nanos() / 64;
                }
            }
            samples.sort_unstable();
            println!("{name} {length} {} {samples:?}", samples[4]);
        }
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--benchmark") {
        benchmark();
        return;
    }
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let count: Vec<_> = line.split(':').collect();
        let [name, key, nonce, aad, input] = count.as_slice() else {
            panic!("invalid oracle input");
        };
        let key = decode(key).try_into().unwrap();
        let nonce = decode(nonce).try_into().unwrap();
        let aad = decode(aad);
        let plain = decode(input);
        let mut cipher = plain.clone();
        let tag = seal(name, &key, &nonce, &aad, &mut cipher);
        for byte in cipher.iter().chain(&tag) {
            print!("{byte:02x}");
        }
        println!();
        open(name, &key, &nonce, &aad, &mut cipher, &tag);
        assert_eq!(cipher, plain);
    }
}
