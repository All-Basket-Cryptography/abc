import { asUint8Array } from '../../../../inputs/bytes.mjs';

// Byte-oriented FIPS 180-4 SHA-256 with a circular message schedule.
const BLOCK_SIZE = 64;
export const MAX_MESSAGE_BYTES = (1n << 61n) - 1n;

const INITIAL = Uint32Array.of(
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
);
const K = Uint32Array.of(
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
);

const rotate = (word, count) => (word >>> count) | (word << (32 - count));

function compress(state, input, offset, schedule) {
  for (let slot = 0; slot < 16; slot += 1) {
    const index = offset + 4 * slot;
    schedule[slot] = (input[index] << 24) | (input[index + 1] << 16) | (input[index + 2] << 8) | input[index + 3];
  }
  let a = state[0], b = state[1], c = state[2], d = state[3];
  let e = state[4], f = state[5], g = state[6], h = state[7];
  for (let round = 0; round < 64; round += 1) {
    const slot = round & 15;
    if (round >= 16) {
      const x = schedule[(round - 15) & 15];
      const y = schedule[(round - 2) & 15];
      const small0 = rotate(x, 7) ^ rotate(x, 18) ^ (x >>> 3);
      const small1 = rotate(y, 17) ^ rotate(y, 19) ^ (y >>> 10);
      schedule[slot] += small0 + schedule[(round - 7) & 15] + small1;
    }
    const choose = g ^ (e & (f ^ g));
    const majority = (a & b) | (c & (a | b));
    const first = h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) + choose + K[round] + schedule[slot];
    const second = (rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) + majority;
    h = g; g = f; f = e; e = (d + first) >>> 0;
    d = c; c = b; b = a; a = (first + second) >>> 0;
  }
  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

function digestScratch() {
  const trailer = new Uint8Array(2 * BLOCK_SIZE);
  return { state: new Uint32Array(8), trailer, bits: new DataView(trailer.buffer) };
}

export class Sha256 {
  #state = INITIAL.slice();
  #tail = new Uint8Array(BLOCK_SIZE);
  #schedule = new Uint32Array(16);
  #digestScratch;
  #used = 0;
  #length = 0n;

  reset() {
    this.#state.set(INITIAL);
    this.#tail.fill(0, 0, this.#used);
    this.#used = 0;
    this.#length = 0n;
  }

  /** Restore an independent copy of a prefix state. */
  copyFrom(source) {
    const used = source.#used;
    this.#state.set(source.#state);
    if (used > 0) this.#tail.set(source.#tail.subarray(0, used));
    if (used < this.#used) this.#tail.fill(0, used, this.#used);
    this.#used = used;
    this.#length = source.#length;
    return this;
  }

  update(input) {
    input = asUint8Array(input);
    if (input.length === 0) return this;
    const length = this.#length + BigInt(input.length);
    if (length > MAX_MESSAGE_BYTES) throw new RangeError('SHA-256 input exceeds the bit-length domain');
    this.#length = length;

    let offset = 0;
    if (this.#used > 0) {
      offset = Math.min(BLOCK_SIZE - this.#used, input.length);
      this.#tail.set(input.subarray(0, offset), this.#used);
      this.#used += offset;
      if (this.#used < BLOCK_SIZE) return this;
      compress(this.#state, this.#tail, 0, this.#schedule);
    }
    while (offset + BLOCK_SIZE <= input.length) {
      compress(this.#state, input, offset, this.#schedule);
      offset += BLOCK_SIZE;
    }
    this.#tail.set(input.subarray(offset));
    this.#used = input.length - offset;
    return this;
  }

  digest() {
    const { state, trailer, bits } = this.#digestScratch ??= digestScratch();
    state.set(this.#state);
    const paddedLength = this.#used < 56 ? BLOCK_SIZE : 2 * BLOCK_SIZE;
    trailer.fill(0, this.#used, paddedLength);
    trailer.set(this.#tail.subarray(0, this.#used));
    trailer[this.#used] = 0x80;
    bits.setBigUint64(paddedLength - 8, this.#length << 3n);
    for (let offset = 0; offset < paddedLength; offset += BLOCK_SIZE) {
      compress(state, trailer, offset, this.#schedule);
    }
    const output = new Uint8Array(32);
    const view = new DataView(output.buffer);
    for (let i = 0; i < state.length; i += 1) view.setUint32(4 * i, state[i]);
    trailer.fill(0, 0, paddedLength);
    return output;
  }
}

export function sha256(input) {
  return new Sha256().update(input).digest();
}
