#![no_main]

use abc_probe::bounded_add;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let mut words = [0; 8];
    for (destination, &byte) in words.iter_mut().zip(input) {
        *destination = byte;
    }
    let [a, b, c, d, e, f, g, h] = words;
    let left = u32::from_le_bytes([a, b, c, d]);
    let raw_right = u32::from_le_bytes([e, f, g, h]);
    let upper_bound = u64::from(u32::MAX) - u64::from(left);
    let right = (u64::from(raw_right) % (upper_bound + 1)) as u32;
    let expected = u64::from(left) + u64::from(right);
    assert_eq!(
        u64::from(bounded_add(left, right)),
        expected,
        "bounded-add differential mismatch"
    );
});
