#![no_std]
#![forbid(unsafe_code)]
//! Table-free byte-oriented AES-256 for research composition.

pub const BLOCK_BYTES: usize = 16;
pub const KEY_BYTES: usize = 32;
const ROUNDS: usize = 14;
const ROUND_WORDS: usize = (ROUNDS + 1) * 4;

pub struct Aes256 {
    words: [u32; ROUND_WORDS],
}

impl Aes256 {
    pub fn new(key: &[u8; KEY_BYTES]) -> Self {
        let mut words = [0; ROUND_WORDS];
        for (word, bytes) in words.iter_mut().zip(key.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        let mut rcon = 1;
        for index in 8..ROUND_WORDS {
            let previous = words[index - 1];
            let derived = match index % 8 {
                0 => {
                    let value = sub_word(previous.rotate_left(8)) ^ (u32::from(rcon) << 24);
                    rcon = mul_x(rcon);
                    value
                }
                4 => sub_word(previous),
                _ => previous,
            };
            words[index] = words[index - 8] ^ derived;
        }
        Self { words }
    }

    pub fn encrypt(&self, block: &mut [u8; BLOCK_BYTES]) {
        self.add_key(block, 0);
        for round in 1..=ROUNDS {
            substitute(block, sbox);
            shift_rows(block, 1);
            if round != ROUNDS {
                for column in block.as_chunks_mut::<4>().0 {
                    mix_column(column);
                }
            }
            self.add_key(block, round);
        }
    }

    pub fn decrypt(&self, block: &mut [u8; BLOCK_BYTES]) {
        self.add_key(block, ROUNDS);
        for round in (0..ROUNDS).rev() {
            shift_rows(block, 3);
            substitute(block, inverse_sbox);
            self.add_key(block, round);
            if round != 0 {
                for column in block.as_chunks_mut::<4>().0 {
                    let even = mul_x(mul_x(column[0] ^ column[2]));
                    let odd = mul_x(mul_x(column[1] ^ column[3]));
                    column[0] ^= even;
                    column[1] ^= odd;
                    column[2] ^= even;
                    column[3] ^= odd;
                    mix_column(column);
                }
            }
        }
    }

    fn add_key(&self, block: &mut [u8; BLOCK_BYTES], round: usize) {
        let words = &self.words[4 * round..][..4];
        for (column, word) in block.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            for (byte, round_byte) in column.iter_mut().zip(word.to_be_bytes()) {
                *byte ^= round_byte;
            }
        }
    }
}

fn sub_word(word: u32) -> u32 {
    u32::from_be_bytes(word.to_be_bytes().map(sbox))
}

fn substitute(block: &mut [u8; BLOCK_BYTES], map: impl Fn(u8) -> u8) {
    for value in block {
        *value = map(*value);
    }
}

fn shift_rows(block: &mut [u8; BLOCK_BYTES], direction: usize) {
    let source = *block;
    for row in 1..4 {
        for column in 0..4 {
            block[4 * column + row] = source[4 * ((column + direction * row) % 4) + row];
        }
    }
}

fn mix_column(column: &mut [u8; 4]) {
    let [a, b, c, d] = *column;
    let xor = a ^ b ^ c ^ d;
    *column = [
        a ^ xor ^ mul_x(a ^ b),
        b ^ xor ^ mul_x(b ^ c),
        c ^ xor ^ mul_x(c ^ d),
        d ^ xor ^ mul_x(d ^ a),
    ];
}

fn mul_x(x: u8) -> u8 {
    let reduce = 0u8.wrapping_sub(x >> 7);
    (x << 1) ^ (0x1b & reduce)
}

fn mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0;
    for _ in 0..8 {
        result ^= left & 0u8.wrapping_sub(right & 1);
        left = mul_x(left);
        right >>= 1;
    }
    result
}

fn square(x: u8) -> u8 {
    // In characteristic two, squaring inserts a zero between coefficients.
    let word = u16::from(x);
    let split = (word | (word << 4)) & 0x0f0f;
    let split = (split | (split << 2)) & 0x3333;
    let spread = (split | (split << 1)) & 0x5555;
    // Reduce first degrees 8–14, then the possible carry up to degree 10.
    let upper = spread >> 8;
    let folded = (spread & 0xff) ^ upper ^ (upper << 1) ^ (upper << 3) ^ (upper << 4);
    let upper = folded >> 8;
    (folded ^ upper ^ (upper << 1) ^ (upper << 3) ^ (upper << 4)) as u8
}

fn inverse(x: u8) -> u8 {
    let x2 = square(x);
    let x3 = mul(x2, x);
    let x6 = square(x3);
    let x7 = mul(x6, x);
    let x14 = square(x7);
    let x15 = mul(x14, x);
    let x30 = square(x15);
    let x60 = square(x30);
    let x120 = square(x60);
    let x127 = mul(x120, x7);
    square(x127)
}

fn sbox(x: u8) -> u8 {
    let y = inverse(x);
    y ^ y.rotate_left(1) ^ y.rotate_left(2) ^ y.rotate_left(3) ^ y.rotate_left(4) ^ 0x63
}

fn inverse_sbox(y: u8) -> u8 {
    inverse(y.rotate_left(1) ^ y.rotate_left(3) ^ y.rotate_left(6) ^ 0x05)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_polynomial_squares_match_multiplication() {
        for x in 0u8..=255 {
            assert_eq!(square(x), mul(x, x));
        }
    }

    #[test]
    fn all_byte_substitutions_invert() {
        for x in 0u8..=255 {
            assert_eq!(inverse_sbox(sbox(x)), x);
            assert_eq!(sbox(inverse_sbox(x)), x);
        }
    }
}
