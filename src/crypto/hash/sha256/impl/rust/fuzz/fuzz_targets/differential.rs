#![no_main]

use abc_sha256::{digest, Sha256};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256 as Oracle};

fuzz_target!(|input: &[u8]| {
    let (control, message) = input.split_at(input.len().min(16));
    let reference: [u8; 32] = Oracle::digest(message).into();
    assert_eq!(
        digest(message).unwrap(),
        reference,
        "SHA-256 one-shot mismatch"
    );

    let mut stream = Sha256::new();
    let mut oracle_stream = Oracle::new();
    let mut remaining = message;
    for &byte in control {
        let count = usize::from(byte & 0x7f).min(remaining.len());
        let (chunk, rest) = remaining.split_at(count);
        stream.update(chunk).unwrap();
        oracle_stream.update(chunk);
        if byte & 0x80 != 0 {
            let checkpoint: [u8; 32] = oracle_stream.clone().finalize().into();
            assert_eq!(
                stream.clone().finalize(),
                checkpoint,
                "SHA-256 stream prefix mismatch"
            );
        }
        remaining = rest;
    }
    stream.update(remaining).unwrap();
    assert_eq!(
        stream.finalize(),
        reference,
        "SHA-256 stream final mismatch"
    );
});
