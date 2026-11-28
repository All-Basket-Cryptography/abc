use std::{hint::black_box, time::Instant};

type Authenticate = fn(&[u8; 32], &[u8]) -> [u8; 16];

fn batch(authenticate: Authenticate, key: &[u8; 32], input: &[u8], calls: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..calls {
        black_box(authenticate(black_box(key), black_box(input)));
    }
    start.elapsed().as_secs_f64() * 1e9 / calls as f64
}

fn main() {
    let implementations: [Authenticate; 2] = [before::authenticate, after::authenticate];
    let key = std::array::from_fn(|index| (index * 131 + 17) as u8);
    for (size, calls) in [
        (1, 65_536),
        (17, 65_536),
        (64, 65_536),
        (65, 65_536),
        (1_025, 16_384),
        (16_384, 1_024),
    ] {
        let input: Vec<u8> = (0..size)
            .map(|index| ((index * 137) ^ (index >> 6)) as u8)
            .collect();
        assert_eq!(
            implementations[0](&key, &input),
            implementations[1](&key, &input)
        );
        for implementation in implementations {
            batch(implementation, &key, &input, calls);
        }
        let mut samples = [[0.0; 11]; 2];
        for sample in 0..11 {
            let first = sample % 2;
            for index in [first, 1 - first] {
                samples[index][sample] = batch(implementations[index], &key, &input, calls);
            }
        }
        for samples in &mut samples {
            samples.sort_by(f64::total_cmp);
        }
        println!(
            "{size} B, {calls} calls per sample: baseline {:.1} (range {:.1}-{:.1}), candidate {:.1} (range {:.1}-{:.1}) ns",
            samples[0][5], samples[0][0], samples[0][10], samples[1][5], samples[1][0], samples[1][10],
        );
    }
}
