// RFC 8439 ChaCha20. The key and nonce are read before any caller output changes.
import { asUint8Array } from '../../../../inputs/bytes.mts';

const MAX_COUNTER = 0xffffffff;
const BLOCK_BYTES = 64;
const CONSTANTS = Uint32Array.of(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574);

function view(bytes: Uint8Array) {
  const view = asUint8Array(bytes);
  return new DataView(view.buffer, view.byteOffset, view.byteLength);
}

function initialState(key: Uint8Array, nonce: Uint8Array, counter: number) {
  const keyView = view(key);
  const nonceView = view(nonce);
  if (keyView.byteLength !== 32 || nonceView.byteLength !== 12) {
    throw new RangeError('ChaCha20 requires a 32-byte key and 12-byte nonce');
  }
  if (!Number.isInteger(counter) || counter < 0 || counter > MAX_COUNTER) {
    throw new RangeError('Invalid ChaCha20 counter');
  }
  const state = new Uint32Array(16);
  state.set(CONSTANTS);
  for (let i = 0; i < 8; i += 1) state[4 + i] = keyView.getUint32(4 * i, true);
  state[12] = counter;
  for (let i = 0; i < 3; i += 1) state[13 + i] = nonceView.getUint32(4 * i, true);
  return state;
}

function rotate(word: number, count: number) {
  return (word << count) | (word >>> (32 - count));
}

function quarter(state: Uint32Array, a: number, b: number, c: number, d: number) {
  state[a] += state[b];
  state[d] = rotate(state[d] ^ state[a], 16);
  state[c] += state[d];
  state[b] = rotate(state[b] ^ state[c], 12);
  state[a] += state[b];
  state[d] = rotate(state[d] ^ state[a], 8);
  state[c] += state[d];
  state[b] = rotate(state[b] ^ state[c], 7);
}

function rounds(initial: Uint32Array, work: Uint32Array) {
  work.set(initial);
  for (let i = 0; i < 10; i += 1) {
    quarter(work, 0, 4, 8, 12);
    quarter(work, 1, 5, 9, 13);
    quarter(work, 2, 6, 10, 14);
    quarter(work, 3, 7, 11, 15);
    quarter(work, 0, 5, 10, 15);
    quarter(work, 1, 6, 11, 12);
    quarter(work, 2, 7, 8, 13);
    quarter(work, 3, 4, 9, 14);
  }
}

export function block(key: Uint8Array, nonce: Uint8Array, counter: number) {
  const initial = initialState(key, nonce, counter);
  const output = new Uint8Array(BLOCK_BYTES);
  const bytes = new DataView(output.buffer);
  const work = new Uint32Array(16);
  rounds(initial, work);
  for (let i = 0; i < work.length; i += 1) bytes.setUint32(4 * i, work[i] + initial[i], true);
  return output;
}

export function applyKeystream(key: Uint8Array, nonce: Uint8Array, counter: number, input: Uint8Array) {
  const destination = asUint8Array(input);
  const initial = initialState(key, nonce, counter);
  const blocks = Math.ceil(destination.length / BLOCK_BYTES);
  if (blocks > MAX_COUNTER + 1 - counter) throw new RangeError('ChaCha20 counter would wrap');
  if (blocks === 0) return input;
  const bytes = new DataView(destination.buffer, destination.byteOffset, destination.byteLength);
  const work = new Uint32Array(16);
  for (let offset = 0; offset < destination.length; offset += BLOCK_BYTES) {
    initial[12] = counter + offset / BLOCK_BYTES;
    rounds(initial, work);
    const size = Math.min(BLOCK_BYTES, destination.length - offset);
    let index = 0;
    for (; index + 4 <= size; index += 4) {
      const mask = work[index >>> 2] + initial[index >>> 2];
      const position = offset + index;
      bytes.setUint32(position, bytes.getUint32(position, true) ^ mask, true);
    }
    if (index < size) {
      const mask = work[index >>> 2] + initial[index >>> 2];
      for (let byte = 0; index + byte < size; byte += 1) {
        destination[offset + index + byte] ^= mask >>> (8 * byte);
      }
    }
  }
  return input;
}
