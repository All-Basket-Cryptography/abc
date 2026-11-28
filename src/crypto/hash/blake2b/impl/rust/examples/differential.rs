use abc_blake2b::{digest, Blake2b};

fn main() {
    for size in 1..=64 {
        for length in [0, 1, 127, 128, 129, 255, 256, 257, 512] {
            let input: Vec<u8> = (0..length).map(|i| (37 * i + 11) as u8).collect();
            let mut expected = vec![0; size];
            let mut streamed = vec![0; size];
            digest(&input, &mut expected).unwrap();
            let mut ctx = Blake2b::new(size).unwrap();
            for chunk in input.chunks(17) {
                ctx.update(chunk).unwrap();
            }
            ctx.finalize(&mut streamed).unwrap();
            assert_eq!(streamed, expected);
            let hex: String = streamed.iter().map(|byte| format!("{byte:02x}")).collect();
            println!("{size}\t{length}\t{hex}");
        }
    }
}
