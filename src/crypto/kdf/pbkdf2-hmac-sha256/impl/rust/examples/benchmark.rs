use abc_pbkdf2_hmac_sha256::derive;
use std::{hint::black_box, num::NonZeroU32, time::Instant};

fn main() {
    let iterations = NonZeroU32::new(4096).unwrap();
    for length in [32, 4096] {
        let password: Vec<u8> = (0..length).map(|i| (i * 31 + 11) as u8).collect();
        let mut output = [0u8; 32];
        derive(
            black_box(&password),
            b"public-benchmark",
            iterations,
            &mut output,
        )
        .unwrap();
        let mut elapsed = Vec::new();
        for _ in 0..9 {
            let begin = Instant::now();
            derive(
                black_box(&password),
                b"public-benchmark",
                iterations,
                &mut output,
            )
            .unwrap();
            black_box(&output);
            elapsed.push(begin.elapsed().as_micros());
        }
        elapsed.sort_unstable();
        println!(
            "{length} B, 4096 iterations, 32-byte output: {} us median, {elapsed:?}",
            elapsed[4]
        );
    }
}
