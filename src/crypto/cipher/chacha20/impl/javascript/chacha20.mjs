// RFC 8439 ChaCha20. The key and nonce are read before any caller output changes.
import { asUint8Array } from '../../../../inputs/bytes.mjs';

const MAX_COUNTER = 0xffffffff;
const BLOCK_BYTES = 64;

function view(bytes) {
  const view = asUint8Array(bytes);
  return new DataView(view.buffer, view.byteOffset, view.byteLength);
}

function initialState(key, nonce, counter) {
  const keyView = view(key);
  const nonceView = view(nonce);
  if (keyView.byteLength !== 32 || nonceView.byteLength !== 12) {
    throw new RangeError('ChaCha20 requires a 32-byte key and 12-byte nonce');
  }
  if (!Number.isInteger(counter) || counter < 0 || counter > MAX_COUNTER) {
    throw new RangeError('Invalid ChaCha20 counter');
  }
  const state = new Uint32Array(16);
  state.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  for (let i = 0; i < 8; i += 1) state[4 + i] = keyView.getUint32(4 * i, true);
  state[12] = counter;
  for (let i = 0; i < 3; i += 1) state[13 + i] = nonceView.getUint32(4 * i, true);
  return state;
}

function rotate(word, count) {
  return (word << count) | (word >>> (32 - count));
}

function quarter(state, a, b, c, d) {
  state[a] += state[b];
  state[d] = rotate(state[d] ^ state[a], 16);
  state[c] += state[d];
  state[b] = rotate(state[b] ^ state[c], 12);
  state[a] += state[b];
  state[d] = rotate(state[d] ^ state[a], 8);
  state[c] += state[d];
  state[b] = rotate(state[b] ^ state[c], 7);
}

function compress(initial, work, out) {
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
  for (let i = 0; i < 16; i += 1) out.setUint32(4 * i, work[i] + initial[i], true);
}

export function block(key, nonce, counter) {
  const initial = initialState(key, nonce, counter);
  const output = new Uint8Array(BLOCK_BYTES);
  compress(initial, new Uint32Array(16), new DataView(output.buffer));
  return output;
}

export function applyKeystream(key, nonce, counter, input) {
  const destination = asUint8Array(input);
  const initial = initialState(key, nonce, counter);
  const blocks = Math.ceil(destination.length / BLOCK_BYTES);
  if (blocks > MAX_COUNTER + 1 - counter) throw new RangeError('ChaCha20 counter would wrap');
  const buffer = new Uint8Array(BLOCK_BYTES);
  const output = new DataView(buffer.buffer);
  const work = new Uint32Array(16);
  for (let offset = 0; offset < destination.length; offset += BLOCK_BYTES) {
    initial[12] = counter + offset / BLOCK_BYTES;
    compress(initial, work, output);
    const size = Math.min(BLOCK_BYTES, destination.length - offset);
    for (let i = 0; i < size; i += 1) destination[offset + i] ^= buffer[i];
  }
  return input;
}
