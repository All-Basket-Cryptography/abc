use abc_aes256_gcm as portable;
use abc_aes256_gcm_accelerated as accelerated;
use std::{hint::black_box, time::Instant};

fn main() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    println!(
        "cpu flags: aes={}, avx={}, pclmulqdq={}, vaes={}",
        std::is_x86_feature_detected!("aes"),
        std::is_x86_feature_detected!("avx"),
        std::is_x86_feature_detected!("pclmulqdq"),
        std::is_x86_feature_detected!("vaes"),
    );
    println!("profile,message_bytes,median_ns_per_seal");
    let mut sequence = 0u64;
    for width in [64, 4096] {
        compare("portable", width, &mut sequence, |key, nonce, aad, data| {
            portable::seal_in_place(key, nonce, aad, data).unwrap()
        });
        compare(
            "accelerated",
            width,
            &mut sequence,
            |key, nonce, aad, data| accelerated::seal_in_place(key, nonce, aad, data).unwrap(),
        );
    }
}

fn compare(
    profile: &str,
    width: usize,
    sequence: &mut u64,
    seal: impl Fn(&[u8; 32], &[u8; 12], &[u8], &mut [u8]) -> [u8; 16],
) {
    const BATCH: usize = 128;
    let key = [17; 32];
    let aad = [29; 16];
    let mut nonce = [0; 12];
    let mut data = vec![0x5b; width];
    let mut samples = [0u128; 5];
    for sample in samples.iter_mut() {
        let start = Instant::now();
        for _ in 0..BATCH {
            nonce[4..].copy_from_slice(&sequence.to_be_bytes());
            *sequence += 1;
            black_box(seal(
                black_box(&key),
                black_box(&nonce),
                black_box(&aad),
                black_box(&mut data),
            ));
        }
        *sample = start.elapsed().as_nanos() / BATCH as u128;
    }
    samples.sort_unstable();
    println!("{profile},{width},{}", samples[samples.len() / 2]);
}
