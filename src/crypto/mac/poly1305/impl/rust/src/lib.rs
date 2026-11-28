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
        let r = clamped_key(*low);
        Self {
            r,
            r_times_five: key_multiples(r),
            h: [0; 5],
            pad: load_block(*high),
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
            self.absorb(self.pending, 1 << 24);
            input = &input[copied..];
        }

        let (blocks, tail) = input.as_chunks::<BLOCK_BYTES>();
        for block in blocks {
            self.absorb(*block, 1 << 24);
        }
        self.pending[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
    }

    /// Consume the context and return its complete 16-byte tag.
    pub fn finalize(mut self) -> [u8; TAG_BYTES] {
        if self.buffered != 0 {
            self.pending[self.buffered..].fill(0);
            self.pending[self.buffered] = 1;
            self.absorb(self.pending, 0);
        }

        finish_tag(self.h, self.pad)
    }

    fn absorb(&mut self, block: [u8; BLOCK_BYTES], high_bit: u64) {
        self.h = absorb_bytes(self.h, self.r, self.r_times_five, block, high_bit);
    }
}

fn select_reduced(original: u64, reduced: u64, mask: u64) -> u64 {
    (original & !mask) | (reduced & mask)
}

fn reduce_final(words: [u64; 5]) -> [u64; 5] {
    let [h0, h1, h2, h3, h4] = words;
    // Adding 5 produces a carry out of limb 4 exactly when h >= 2^130 - 5.
    let (r0, c1) = carry_pair(h0 + 5, h1);
    let (r1, c2) = carry_pair(c1, h2);
    let (r2, c3) = carry_pair(c2, h3);
    let (r3, c4) = carry_pair(c3, h4);
    let mask = 0u64.wrapping_sub(c4 >> RADIX_BITS);
    let r4 = c4 & LIMB_MASK;
    [
        select_reduced(h0, r0, mask),
        select_reduced(h1, r1, mask),
        select_reduced(h2, r2, mask),
        select_reduced(h3, r3, mask),
        select_reduced(h4, r4, mask),
    ]
}

fn pack_low128(words: [u64; 5]) -> u128 {
    let [h0, h1, h2, h3, h4] = words;
    (h0 as u128)
        | ((h1 as u128) << RADIX_BITS)
        | ((h2 as u128) << (2 * RADIX_BITS))
        | ((h3 as u128) << (3 * RADIX_BITS))
        | ((h4 as u128) << (4 * RADIX_BITS))
}

fn add_pad_and_serialize(low: u128, pad: u128) -> [u8; TAG_BYTES] {
    low.wrapping_add(pad).to_le_bytes()
}

fn finish_tag(words: [u64; 5], pad: u128) -> [u8; TAG_BYTES] {
    // Absorption finishes by carrying any excess from limb 0 into limb 1.
    let normalized = carry_upper(words);
    let reduced = reduce_final(normalized);
    add_pad_and_serialize(pack_low128(reduced), pad)
}

fn load_block(block: [u8; BLOCK_BYTES]) -> u128 {
    u128::from_le_bytes(block)
}

fn clamped_key(block: [u8; BLOCK_BYTES]) -> [u64; 5] {
    limbs(load_block(block) & 0x0ffffffc0ffffffc0ffffffc0fffffff)
}

fn key_multiples(r: [u64; 5]) -> [u64; 4] {
    let [_, r1, r2, r3, r4] = r;
    [r1 * 5, r2 * 5, r3 * 5, r4 * 5]
}

fn absorb_bytes(
    h: [u64; 5],
    r: [u64; 5],
    r_five: [u64; 4],
    block: [u8; BLOCK_BYTES],
    high_bit: u64,
) -> [u64; 5] {
    absorb_encoded(h, r, r_five, load_block(block), high_bit)
}

fn absorb_encoded(
    h: [u64; 5],
    r: [u64; 5],
    r_five: [u64; 4],
    value: u128,
    high_bit: u64,
) -> [u64; 5] {
    let mut message = limbs(value);
    message[4] |= high_bit;
    absorb_limbs(h, r, r_five, message)
}

fn absorb_limbs(h: [u64; 5], r: [u64; 5], r_five: [u64; 4], message: [u64; 5]) -> [u64; 5] {
    let [h0, h1, h2, h3, h4] = h;
    let [m0, m1, m2, m3, m4] = message;
    let input = [h0 + m0, h1 + m1, h2 + m2, h3 + m3, h4 + m4];
    carry(multiply(input, r, r_five))
}

fn multiply(h: [u64; 5], r: [u64; 5], r_five: [u64; 4]) -> [u64; 5] {
    let [h0, h1, h2, h3, h4] = h;
    let [r0, r1, r2, r3, r4] = r;
    let [r1_5, r2_5, r3_5, r4_5] = r_five;

    // When a term crosses limb 4, fold it with 2^130 congruent to 5.
    [
        h0 * r0 + h1 * r4_5 + h2 * r3_5 + h3 * r2_5 + h4 * r1_5,
        h0 * r1 + h1 * r0 + h2 * r4_5 + h3 * r3_5 + h4 * r2_5,
        h0 * r2 + h1 * r1 + h2 * r0 + h3 * r4_5 + h4 * r3_5,
        h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * r4_5,
        h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0,
    ]
}

fn limbs(value: u128) -> [u64; 5] {
    [
        (value as u64) & LIMB_MASK,
        ((value >> RADIX_BITS) as u64) & LIMB_MASK,
        ((value >> (2 * RADIX_BITS)) as u64) & LIMB_MASK,
        ((value >> (3 * RADIX_BITS)) as u64) & LIMB_MASK,
        ((value >> (4 * RADIX_BITS)) as u64) & LIMB_MASK,
    ]
}

fn carry_pair(low: u64, high: u64) -> (u64, u64) {
    (low & LIMB_MASK, high + (low >> RADIX_BITS))
}

fn carry(words: [u64; 5]) -> [u64; 5] {
    let [h0, h1, h2, h3, h4] = words;
    let (h0, h1) = carry_pair(h0, h1);
    carry_upper([h0, h1, h2, h3, h4])
}

fn carry_upper(words: [u64; 5]) -> [u64; 5] {
    let [h0, h1, h2, h3, h4] = words;
    let (h1, h2) = carry_pair(h1, h2);
    let (h2, h3) = carry_pair(h2, h3);
    let (h3, h4) = carry_pair(h3, h4);
    let h0 = h0 + (h4 >> RADIX_BITS) * 5;
    let h4 = h4 & LIMB_MASK;
    let (h0, h1) = carry_pair(h0, h1);
    [h0, h1, h2, h3, h4]
}

pub fn authenticate(key: &[u8; KEY_BYTES], input: &[u8]) -> [u8; TAG_BYTES] {
    let mut state = Poly1305::new(key);
    state.update(input);
    state.finalize()
}
