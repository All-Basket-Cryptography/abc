use crate::{Block, BLOCK_WORDS};

// RFC 9106 § 3.5. Each matrix cell consists of two consecutive words.
pub(super) fn compress(left: &Block, right: &Block) -> Block {
    let mut mixed = [0; BLOCK_WORDS];
    for ((word, left), right) in mixed.iter_mut().zip(left).zip(right) {
        *word = left ^ right;
    }
    let mut state = mixed;
    for row in state.as_chunks_mut::<16>().0 {
        permute(row);
    }
    for column in 0..8 {
        let mut words = [0; 16];
        for (row, pair) in words.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            let offset = 16 * row + 2 * column;
            pair.copy_from_slice(&state[offset..offset + 2]);
        }
        permute(&mut words);
        for (row, pair) in words.as_chunks::<2>().0.iter().enumerate() {
            let offset = 16 * row + 2 * column;
            state[offset..offset + 2].copy_from_slice(pair);
        }
    }
    for (word, original) in state.iter_mut().zip(mixed) {
        *word ^= original;
    }
    state
}

fn permute(words: &mut [u64; 16]) {
    for column in 0..4 {
        quarter(words, [column, column + 4, column + 8, column + 12]);
    }
    for column in 0..4 {
        quarter(
            words,
            [
                column,
                4 + (column + 1) % 4,
                8 + (column + 2) % 4,
                12 + (column + 3) % 4,
            ],
        );
    }
}

fn quarter(words: &mut [u64; 16], [ai, bi, ci, di]: [usize; 4]) {
    let (mut a, mut b, mut c, mut d) = (words[ai], words[bi], words[ci], words[di]);
    a = mix(a, b);
    d = (d ^ a).rotate_right(32);
    c = mix(c, d);
    b = (b ^ c).rotate_right(24);
    a = mix(a, b);
    d = (d ^ a).rotate_right(16);
    c = mix(c, d);
    b = (b ^ c).rotate_right(63);
    (words[ai], words[bi], words[ci], words[di]) = (a, b, c, d);
}

fn mix(left: u64, right: u64) -> u64 {
    let low_product = u64::from(left as u32) * u64::from(right as u32);
    left.wrapping_add(right).wrapping_add(low_product << 1)
}
