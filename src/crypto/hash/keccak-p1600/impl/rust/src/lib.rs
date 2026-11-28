#![no_std]
#![forbid(unsafe_code)]

//! FIPS 202 Keccak-p[1600, 24] on lanes ordered by x + 5y.

pub const RATE_BYTES: usize = 136;

// Rotation offsets from FIPS 202 Table 2, indexed by y then x.
const ROTATION: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

// Iota constants obtained from FIPS 202 Algorithm 5 and Algorithm 6.
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

pub fn absorb_rate_block(state: &mut [u64; 25], block: &[u8; RATE_BYTES]) {
    for (lane, chunk) in state.iter_mut().zip(block.as_chunks::<8>().0) {
        *lane ^= u64::from_le_bytes(*chunk);
    }
    keccak_p1600(state);
}

pub fn keccak_p1600(state: &mut [u64; 25]) {
    // The flattened lane index is x + 5y.
    for constant in ROUND_CONSTANTS {
        let mut parity = [0; 5];
        for row in state.as_chunks::<5>().0 {
            for (column, lane) in parity.iter_mut().zip(row) {
                *column ^= lane;
            }
        }
        let mut shuffled = [0; 25];
        for (y, rotations) in ROTATION.iter().enumerate() {
            for (x, rotation) in rotations.iter().enumerate() {
                // Theta, rho and pi.
                let theta = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
                shuffled[y + 5 * ((2 * x + 3 * y) % 5)] =
                    (state[x + 5 * y] ^ theta).rotate_left(*rotation);
            }
        }
        for (row, source) in state
            .as_chunks_mut::<5>()
            .0
            .iter_mut()
            .zip(shuffled.as_chunks::<5>().0)
        {
            for (x, lane) in row.iter_mut().enumerate() {
                // Chi.
                *lane = source[x] ^ (!source[(x + 1) % 5] & source[(x + 2) % 5]);
            }
        }
        // Iota.
        state[0] ^= constant;
    }
}
