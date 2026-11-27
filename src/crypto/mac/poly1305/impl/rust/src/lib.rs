#![no_std]
#![forbid(unsafe_code)]
//! Byte-oriented Poly1305 from RFC 8439. Each key is for one message.

pub const KEY_BYTES: usize = 32;
pub const TAG_BYTES: usize = 16;

const BLOCK_BYTES: usize = 16;
const RADIX_BITS: u32 = 26;
const LIMB_MASK: u64 = (1 << RADIX_BITS) - 1;

pub struct Poly1305 {
    r: [u64; 5],
    r_times_five: [u64; 4],
    h: [u64; 5],
    pad: u128,
    pending: [u8; BLOCK_BYTES],
    buffered: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; KEY_BYTES]) -> Self {
        let [low, high] = key.as_chunks::<BLOCK_BYTES>().0 else {
            unreachable!("Poly1305 key size is fixed");
        };
        let clamped = u128::from_le_bytes(*low) & 0x0ffffffc0ffffffc0ffffffc0fffffff;
        let r = limbs(clamped);
        let [_, r1, r2, r3, r4] = r;
        Self {
            r,
            r_times_five: [r1 * 5, r2 * 5, r3 * 5, r4 * 5],
            h: [0; 5],
            pad: u128::from_le_bytes(*high),
            pending: [0; BLOCK_BYTES],
            buffered: 0,
        }
    }

    /// Absorb arbitrary chunks before finalization.
    pub fn update(&mut self, mut input: &[u8]) {
        if self.buffered != 0 {
            let copied = input.len().min(BLOCK_BYTES - self.buffered);
            let end = self.buffered + copied;
            self.pending[self.buffered..end].copy_from_slice(&input[..copied]);
            self.buffered = end;
            if end < BLOCK_BYTES {
                return;
            }
            self.absorb(u128::from_le_bytes(self.pending), 1 << 24);
            input = &input[copied..];
        }

        let (blocks, tail) = input.as_chunks::<BLOCK_BYTES>();
        for block in blocks {
            self.absorb(u128::from_le_bytes(*block), 1 << 24);
        }
        self.pending[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
    }

    /// Consume the context and return its complete 16-byte tag.
    pub fn finalize(mut self) -> [u8; TAG_BYTES] {
        if self.buffered != 0 {
            self.pending[self.buffered..].fill(0);
            self.pending[self.buffered] = 1;
            self.absorb(u128::from_le_bytes(self.pending), 0);
        }

        // Absorption finishes by carrying any excess from limb 0 into limb 1.
        carry(&mut self.h, 1);

        // Adding 5 produces a carry out of limb 4 exactly when h >= 2^130 - 5.
        let mut reduced = self.h;
        reduced[0] += 5;
        for index in 0..4 {
            reduced[index + 1] += reduced[index] >> RADIX_BITS;
            reduced[index] &= LIMB_MASK;
        }
        let select = 0u64.wrapping_sub(reduced[4] >> RADIX_BITS);
        reduced[4] &= LIMB_MASK;
        let mut low = 0u128;
        for (index, (word, choice)) in self.h.into_iter().zip(reduced).enumerate() {
            low |=
                (u128::from((word & !select) | (choice & select))) << (index * RADIX_BITS as usize);
        }
        low.wrapping_add(self.pad).to_le_bytes()
    }

    fn absorb(&mut self, value: u128, high_bit: u64) {
        let mut message = limbs(value);
        message[4] |= high_bit;
        for (word, input) in self.h.iter_mut().zip(message) {
            *word += input;
        }
        let [h0, h1, h2, h3, h4] = self.h;
        let [r0, r1, r2, r3, r4] = self.r;
        let [r1_5, r2_5, r3_5, r4_5] = self.r_times_five;

        // When a term crosses limb 4, fold it with 2^130 congruent to 5.
        self.h = [
            h0 * r0 + h1 * r4_5 + h2 * r3_5 + h3 * r2_5 + h4 * r1_5,
            h0 * r1 + h1 * r0 + h2 * r4_5 + h3 * r3_5 + h4 * r2_5,
            h0 * r2 + h1 * r1 + h2 * r0 + h3 * r4_5 + h4 * r3_5,
            h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * r4_5,
            h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0,
        ];
        carry(&mut self.h, 0);
    }
}

fn limbs(value: u128) -> [u64; 5] {
    core::array::from_fn(|index| ((value >> (index * RADIX_BITS as usize)) as u64) & LIMB_MASK)
}

fn carry(words: &mut [u64; 5], first: usize) {
    for index in first..4 {
        words[index + 1] += words[index] >> RADIX_BITS;
        words[index] &= LIMB_MASK;
    }
    words[0] += (words[4] >> RADIX_BITS) * 5;
    words[4] &= LIMB_MASK;
    words[1] += words[0] >> RADIX_BITS;
    words[0] &= LIMB_MASK;
}

pub fn authenticate(key: &[u8; KEY_BYTES], input: &[u8]) -> [u8; TAG_BYTES] {
    let mut state = Poly1305::new(key);
    state.update(input);
    state.finalize()
}
