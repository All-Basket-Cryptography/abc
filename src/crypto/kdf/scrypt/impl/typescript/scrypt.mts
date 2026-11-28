import { asUint8Array } from '../../../../inputs/bytes.mts';
import { derive as pbkdf2, MAX_OUTPUT_BYTES } from '../../../pbkdf2-hmac-sha256/impl/typescript/pbkdf2.mts';

export interface ScryptOptions {
  cost: number;
  blockSize: number;
  parallel: number;
  length: number;
  memoryLimit: number;
}

// RFC 7914 with same-language PBKDF2-HMAC-SHA-256 and a reusable ROMix table.
const MAX_BUFFER = 0x7fffffff;
const BLOCK_BYTES = 64;
const STATE_WORDS = BLOCK_BYTES / 4;

function layout(cost: number, blockSize: number, parallel: number) {
  if (!Number.isSafeInteger(cost) || !Number.isSafeInteger(blockSize)
      || !Number.isSafeInteger(parallel) || cost < 2 || blockSize < 1 || parallel < 1) {
    throw new RangeError('scrypt requires positive integer parameters and N > 1');
  }
  const n = BigInt(cost);
  if ((n & (n - 1n)) !== 0n || n.toString(2).length - 1 >= 16 * blockSize) {
    throw new RangeError('scrypt requires N to be a power of two below 2^(16r)');
  }
  const stride = 128n * BigInt(blockSize);
  const lanes = stride * BigInt(parallel);
  const table = stride * n;
  if (lanes > BigInt(MAX_OUTPUT_BYTES) || table + lanes + 2n * stride + 128n > BigInt(MAX_BUFFER)) {
    throw new RangeError('scrypt input lanes or working arrays exceed the profile size limit');
  }
  return { stride: Number(stride), lanes: Number(lanes), table: Number(table) };
}

function rotate(word: number, count: number) {
  return (word << count) | (word >>> (32 - count));
}

function quarter(words: Uint32Array, a: number, b: number, c: number, d: number) {
  words[b] ^= rotate(words[a] + words[d], 7);
  words[c] ^= rotate(words[b] + words[a], 9);
  words[d] ^= rotate(words[c] + words[b], 13);
  words[a] ^= rotate(words[d] + words[c], 18);
}

function salsa8(state: Uint32Array, scratch: Uint32Array) {
  scratch.set(state);
  for (let i = 0; i < 4; i += 1) {
    quarter(scratch, 0, 4, 8, 12);
    quarter(scratch, 5, 9, 13, 1);
    quarter(scratch, 10, 14, 2, 6);
    quarter(scratch, 15, 3, 7, 11);
    quarter(scratch, 0, 1, 2, 3);
    quarter(scratch, 5, 6, 7, 4);
    quarter(scratch, 10, 11, 8, 9);
    quarter(scratch, 15, 12, 13, 14);
  }
  for (let i = 0; i < STATE_WORDS; i += 1) state[i] += scratch[i];
}

function blockMix(lane: Uint32Array, reordered: Uint32Array, state: Uint32Array, scratch: Uint32Array) {
  const blocks = lane.length / STATE_WORDS;
  for (let i = 0; i < STATE_WORDS; i += 1) state[i] = lane[lane.length - STATE_WORDS + i];
  for (let block = 0; block < blocks; block += 1) {
    for (let i = 0; i < STATE_WORDS; i += 1) state[i] ^= lane[block * STATE_WORDS + i];
    salsa8(state, scratch);
    const position = (Math.floor(block / 2) + (block % 2) * (blocks / 2)) * STATE_WORDS;
    reordered.set(state, position);
  }
  lane.set(reordered);
}

export function workspaceSize(cost: number, blockSize: number, parallel: number) {
  const { stride, lanes, table } = layout(cost, blockSize, parallel);
  return lanes + table + 2 * stride + 128;
}

export function derive(password: Uint8Array, salt: Uint8Array, options: ScryptOptions) {
  const { cost, blockSize, parallel, length, memoryLimit } = options;
  const { stride, lanes, table } = layout(cost, blockSize, parallel);
  if (!Number.isSafeInteger(length) || length < 1 || length > MAX_BUFFER) {
    throw new RangeError('scrypt output length is outside the portable allocation limits');
  }
  if (!Number.isSafeInteger(memoryLimit)
      || memoryLimit < lanes + table + 2 * stride + 128 + length) {
    throw new RangeError('scrypt work arrays and output exceed the memory limit');
  }
  const key = asUint8Array(password);
  const saltBytes = asUint8Array(salt);
  const history = new Uint32Array(table / 4);
  const lane = new Uint32Array(stride / 4);
  const reordered = new Uint32Array(lane.length);
  const state = new Uint32Array(STATE_WORDS);
  const scratch = new Uint32Array(STATE_WORDS);
  const data = pbkdf2(key, saltBytes, 1, lanes);
  try {
    const views = new DataView(data.buffer, data.byteOffset, data.byteLength);
    for (let offset = 0; offset < lanes; offset += stride) {
      for (let i = 0; i < lane.length; i += 1) lane[i] = views.getUint32(offset + i * 4, true);
      for (let i = 0; i < cost; i += 1) {
        history.set(lane, i * lane.length);
        blockMix(lane, reordered, state, scratch);
      }
      for (let i = 0; i < cost; i += 1) {
        // The allocation cap bounds N below 2^32, so Integerify needs only the low word.
        const slot = (lane[lane.length - STATE_WORDS] & (cost - 1)) * lane.length;
        for (let j = 0; j < lane.length; j += 1) lane[j] ^= history[slot + j];
        blockMix(lane, reordered, state, scratch);
      }
      for (let i = 0; i < lane.length; i += 1) views.setUint32(offset + i * 4, lane[i], true);
    }
    return pbkdf2(key, data, 1, length);
  } finally {
    for (const buffer of [data, history, lane, reordered, state, scratch]) buffer.fill(0);
  }
}
