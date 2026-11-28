use std::hint::black_box;
use std::time::Instant;

fn measure(size: usize, calls: usize, backend: fn(&[u8; 32], &[u8; 12], &mut [u8])) -> f64 {
    let mut message = vec![0x42; size];
    let key = [17; 32];
    let nonce = [113; 12];
    for _ in 0..1000 {
        backend(black_box(&key), black_box(&nonce), black_box(&mut message));
    }
    let started = Instant::now();
    for _ in 0..calls {
        backend(black_box(&key), black_box(&nonce), black_box(&mut message));
    }
    started.elapsed().as_nanos() as f64 / calls as f64
}

fn main() {
    let old = |key: &[u8; 32], nonce: &[u8; 12], message: &mut [u8]| {
        abc_old::apply_keystream(key, nonce, 1, message).unwrap();
    };
    let new = |key: &[u8; 32], nonce: &[u8; 12], message: &mut [u8]| {
        abc_new::apply_keystream(key, nonce, 1, message).unwrap();
    };
    for size in [64, 1024, 16_384] {
        let calls = 10_000_000 / size;
        let mut before = [0f64; 7];
        let mut after = [0f64; 7];
        for run in 0..7 {
            if run % 2 == 0 {
                before[run] = measure(size, calls, old);
                after[run] = measure(size, calls, new);
            } else {
                after[run] = measure(size, calls, new);
                before[run] = measure(size, calls, old);
            }
        }
        before.sort_by(f64::total_cmp);
        after.sort_by(f64::total_cmp);
        println!(
            "{size} bytes, {calls} calls per sample, before {:.1} ns, after {:.1} ns",
            before[3], after[3]
        );
    }
}
