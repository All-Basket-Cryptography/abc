use abc_ecdsa_p256_sha256::{public_key, sign, verify};
use std::io::{self, BufRead};

fn decode(encoded: &str) -> Vec<u8> {
    (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let parts: Vec<_> = line.split(':').collect();
        let [private, message, foreign_signature] = parts.as_slice() else {
            panic!("expected private key, message and OpenSSL signature");
        };
        let private = decode(private).try_into().unwrap();
        let message = decode(message);
        let foreign_signature = decode(foreign_signature).try_into().unwrap();
        let public = public_key(&private).unwrap();
        let signature = sign(&private, &message).unwrap();
        assert_eq!(sign(&private, &message).unwrap(), signature);
        verify(&public, &message, &foreign_signature).unwrap();
        for byte in public {
            print!("{byte:02x}");
        }
        print!(":");
        for byte in signature {
            print!("{byte:02x}");
        }
        println!();
    }
}
