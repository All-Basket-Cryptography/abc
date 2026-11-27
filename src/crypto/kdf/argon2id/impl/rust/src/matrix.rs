use crate::compress::compress;
use crate::{long_hash, Block, Parameters, BLOCK_BYTES, BLOCK_WORDS, SLICES, VARIANT};

pub(super) fn initialize(memory: &mut [Block], parameters: Parameters, h0: &[u8; 64]) {
    let mut seed = [0; 72];
    seed[..64].copy_from_slice(h0);
    for (lane, blocks) in memory
        .chunks_exact_mut(parameters.lane_blocks())
        .enumerate()
    {
        seed[68..].copy_from_slice(&(lane as u32).to_le_bytes());
        for (index, block) in blocks[..2].iter_mut().enumerate() {
            seed[64..68].copy_from_slice(&(index as u32).to_le_bytes());
            let mut encoded = [0; BLOCK_BYTES];
            long_hash(&seed, &mut encoded);
            for (word, bytes) in block.iter_mut().zip(encoded.as_chunks::<8>().0) {
                *word = u64::from_le_bytes(*bytes);
            }
        }
    }
}

pub(super) fn fill_pass(memory: &mut [Block], parameters: Parameters, pass: u32) {
    for slice in 0..SLICES {
        // Different lanes in this slice do not reference each other in the slice.
        for lane in 0..parameters.lanes {
            fill_segment(memory, parameters, pass, slice, lane);
        }
    }
}

fn fill_segment(
    memory: &mut [Block],
    parameters: Parameters,
    pass: u32,
    slice: usize,
    lane: usize,
) {
    let first = if pass == 0 && slice == 0 { 2 } else { 0 };
    let mut addresses =
        (pass == 0 && slice < SLICES / 2).then(|| AddressBlock::new(parameters, pass, slice, lane));
    let lane_blocks = parameters.lane_blocks();
    let lane_base = lane * lane_blocks;
    for index in first..parameters.segment_blocks {
        let column = slice * parameters.segment_blocks + index;
        let preceding_column = if column == 0 {
            lane_blocks - 1
        } else {
            column - 1
        };
        let preceding = &memory[lane_base + preceding_column];
        let pseudo = match addresses.as_mut() {
            Some(addresses) => addresses.word(index, first),
            None => preceding[0],
        };
        let reference_lane = if pass == 0 && slice == 0 {
            lane
        } else {
            ((pseudo >> 32) % parameters.lanes as u64) as usize
        };
        let reference_column = reference_column(
            parameters,
            pass,
            slice,
            index,
            reference_lane == lane,
            pseudo as u32,
        );
        let reference = &memory[reference_lane * lane_blocks + reference_column];
        let result = compress(preceding, reference);
        let destination = &mut memory[lane_base + column];
        if pass == 0 {
            *destination = result;
        } else {
            for (word, next) in destination.iter_mut().zip(result) {
                *word ^= next;
            }
        }
    }
}

fn reference_column(
    parameters: Parameters,
    pass: u32,
    slice: usize,
    index: usize,
    same_lane: bool,
    j1: u32,
) -> usize {
    let lane_blocks = parameters.lane_blocks();
    let segment = parameters.segment_blocks;
    let finished = if pass == 0 {
        slice * segment
    } else {
        lane_blocks - segment
    };
    let area = if same_lane {
        finished + index - 1
    } else {
        finished - usize::from(index == 0)
    };
    // Both multiplications fit in u64: j1 and the reference area fit in u32.
    let j1 = u64::from(j1);
    let relative = area - 1 - ((area as u64 * ((j1 * j1) >> 32)) >> 32) as usize;
    let start = if pass != 0 && slice != SLICES - 1 {
        (slice + 1) * segment
    } else {
        0
    };
    (start + relative) % lane_blocks
}

struct AddressBlock {
    input: Block,
    output: Block,
}

impl AddressBlock {
    fn new(parameters: Parameters, pass: u32, slice: usize, lane: usize) -> Self {
        let mut input = [0; BLOCK_WORDS];
        input[..6].copy_from_slice(&[
            u64::from(pass),
            lane as u64,
            slice as u64,
            parameters.block_count as u64,
            u64::from(parameters.iterations),
            u64::from(VARIANT),
        ]);
        Self {
            input,
            output: [0; BLOCK_WORDS],
        }
    }

    fn word(&mut self, index: usize, first: usize) -> u64 {
        if index == first || index.is_multiple_of(BLOCK_WORDS) {
            const ZERO: Block = [0; BLOCK_WORDS];
            self.input[6] += 1;
            self.output = compress(&ZERO, &compress(&ZERO, &self.input));
        }
        self.output[index % BLOCK_WORDS]
    }
}
