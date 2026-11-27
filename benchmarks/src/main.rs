use abc_sha256::digest;
use std::hint::black_box;
use std::time::Instant;

const SIZES: [usize; 9] = [0, 55, 56, 63, 64, 65, 1024, 16_384, 1_048_576];
const POOL: usize = 8;
const WARMUP: usize = 3;
const ROUNDS: usize = 15;
const INPUT_SEED: u64 = 48_735_132;

struct Case {
    size: usize,
    iterations: usize,
    inputs: Vec<Vec<u8>>,
}

fn next_byte(state: &mut u64) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state as u8
}

fn measure(case: &Case) -> u128 {
    let start = Instant::now();
    for iteration in 0..case.iterations {
        let bytes = &case.inputs[iteration % POOL];
        black_box(digest(black_box(bytes.as_slice())).expect("benchmark input fits the API"));
    }
    start.elapsed().as_nanos()
}

fn main() {
    let mut seed = INPUT_SEED;
    let cases: Vec<_> = SIZES
        .iter()
        .map(|&size| Case {
            size,
            iterations: (2_097_152 / size.max(1)).clamp(16, 80_000),
            inputs: (0..POOL)
                .map(|_| (0..size).map(|_| next_byte(&mut seed)).collect())
                .collect(),
        })
        .collect();

    println!("abc-benchmark-v1\t{POOL}\t{WARMUP}\t{ROUNDS}\t{INPUT_SEED}");
    for case in &cases {
        for _ in 0..WARMUP {
            black_box(measure(case));
        }
    }
    for round in 0..ROUNDS {
        // Change the first measured size between rounds to spread timing drift.
        for offset in 0..cases.len() {
            let case = &cases[(round + offset) % cases.len()];
            println!(
                "{round}\t{}\t{}\t{}",
                case.size,
                case.iterations,
                measure(case)
            );
        }
    }
}
