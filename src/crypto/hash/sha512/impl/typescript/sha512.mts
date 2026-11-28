import { asUint8Array } from '../../../../inputs/bytes.mts';

// Byte-oriented FIPS 180-4 SHA-512 using two unsigned limbs per word.
const BLOCK_SIZE = 128;
const LENGTH_START = 112;
const RADIX = 0x100000000;
const MASK64 = (1n << 64n) - 1n;
export const MAX_MESSAGE_BYTES = (1n << 125n) - 1n;

const INITIAL = Uint32Array.of(
  0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b,
  0xa54ff53a, 0x5f1d36f1, 0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
  0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
);
const ROUND_CONSTANTS = Uint32Array.of(
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f,
  0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
  0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242,
  0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235,
  0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
  0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65, 0x2de92c6f, 0x592b0275,
  0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f,
  0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc,
  0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6,
  0x92722c85, 0x1482353b, 0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
  0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218,
  0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99,
  0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
  0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc,
  0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915,
  0xc67178f2, 0xe372532b, 0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
  0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178, 0x06f067aa, 0x72176fba,
  0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc,
  0x431d67c4, 0x9c100d4c, 0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
  0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
);

// The SHA-512 rotation offsets are all in 1..63 and exclude 32.
// Calling with the limbs reversed gives the other half of the result.
function rotateHalf(high: number, low: number, distance: number) {
  if (distance < 32) return (high >>> distance) | (low << (32 - distance));
  return (low >>> (distance - 32)) | (high << (64 - distance));
}

function compress(state: Uint32Array, input: DataView, offset: number, schedule: Uint32Array) {
  for (let i = 0; i < 32; i += 1) schedule[i] = input.getUint32(offset + 4 * i);
  let [ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl] = state;
  for (let round = 0; round < 80; round += 1) {
    const slot = 2 * (round & 15);
    if (round >= 16) {
      const x = 2 * ((round - 15) & 15);
      const y = 2 * ((round - 2) & 15);
      const past = 2 * ((round - 7) & 15);
      const xh = schedule[x], xl = schedule[x + 1], yh = schedule[y], yl = schedule[y + 1];
      const low0 = (rotateHalf(xl, xh, 1) ^ rotateHalf(xl, xh, 8) ^ ((xl >>> 7) | (xh << 25))) >>> 0;
      const high0 = (rotateHalf(xh, xl, 1) ^ rotateHalf(xh, xl, 8) ^ (xh >>> 7)) >>> 0;
      const low1 = (rotateHalf(yl, yh, 19) ^ rotateHalf(yl, yh, 61) ^ ((yl >>> 6) | (yh << 26))) >>> 0;
      const high1 = (rotateHalf(yh, yl, 19) ^ rotateHalf(yh, yl, 61) ^ (yh >>> 6)) >>> 0;
      const lower = schedule[slot + 1] + low0 + schedule[past + 1] + low1;
      schedule[slot] += high0 + schedule[past] + high1 + Math.floor(lower / RADIX);
      schedule[slot + 1] = lower;
    }

    const upper1L = (rotateHalf(el, eh, 14) ^ rotateHalf(el, eh, 18) ^ rotateHalf(el, eh, 41)) >>> 0;
    const upper1H = (rotateHalf(eh, el, 14) ^ rotateHalf(eh, el, 18) ^ rotateHalf(eh, el, 41)) >>> 0;
    const chooseL = (gl ^ (el & (fl ^ gl))) >>> 0;
    const chooseH = (gh ^ (eh & (fh ^ gh))) >>> 0;
    const firstL = hl + upper1L + chooseL + ROUND_CONSTANTS[2 * round + 1] + schedule[slot + 1];
    const firstH = hh + upper1H + chooseH + ROUND_CONSTANTS[2 * round] + schedule[slot]
      + Math.floor(firstL / RADIX);

    const upper0L = (rotateHalf(al, ah, 28) ^ rotateHalf(al, ah, 34) ^ rotateHalf(al, ah, 39)) >>> 0;
    const upper0H = (rotateHalf(ah, al, 28) ^ rotateHalf(ah, al, 34) ^ rotateHalf(ah, al, 39)) >>> 0;
    const majorityL = ((al & bl) | (cl & (al | bl))) >>> 0;
    const majorityH = ((ah & bh) | (ch & (ah | bh))) >>> 0;
    const secondL = upper0L + majorityL;
    const secondH = upper0H + majorityH + Math.floor(secondL / RADIX);

    const nextAL = (firstL >>> 0) + (secondL >>> 0);
    const nextEL = dl + (firstL >>> 0);
    hh = gh; hl = gl;
    gh = fh; gl = fl;
    fh = eh; fl = el;
    eh = (dh + firstH + Math.floor(nextEL / RADIX)) >>> 0;
    el = nextEL >>> 0;
    dh = ch; dl = cl;
    ch = bh; cl = bl;
    bh = ah; bl = al;
    ah = (firstH + secondH + Math.floor(nextAL / RADIX)) >>> 0;
    al = nextAL >>> 0;
  }

  const working = [ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl];
  for (let i = 0; i < state.length; i += 2) {
    const lower = state[i + 1] + working[i + 1];
    state[i] += working[i] + Math.floor(lower / RADIX);
    state[i + 1] = lower;
  }
}

export class Sha512 {
  #state = INITIAL.slice();
  #tail = new Uint8Array(BLOCK_SIZE);
  #schedule = new Uint32Array(32);
  #used = 0;
  #length: bigint = 0n;

  reset() {
    this.#state.set(INITIAL);
    this.#used = 0;
    this.#length = 0n;
  }

  update(input: Uint8Array) {
    input = asUint8Array(input);
    const length = this.#length + BigInt(input.length);
    if (length > MAX_MESSAGE_BYTES) throw new RangeError('SHA-512 input exceeds the bit-length domain');
    const data = new DataView(input.buffer, input.byteOffset, input.byteLength);
    this.#length = length;

    let offset = 0;
    if (this.#used > 0) {
      offset = Math.min(BLOCK_SIZE - this.#used, input.length);
      this.#tail.set(input.subarray(0, offset), this.#used);
      this.#used += offset;
      if (this.#used < BLOCK_SIZE) return this;
      compress(this.#state, new DataView(this.#tail.buffer), 0, this.#schedule);
    }
    while (offset + BLOCK_SIZE <= input.length) {
      compress(this.#state, data, offset, this.#schedule);
      offset += BLOCK_SIZE;
    }
    this.#tail.set(input.subarray(offset));
    this.#used = input.length - offset;
    return this;
  }

  digest(): Uint8Array {
    const state = this.#state.slice();
    const trailer = new Uint8Array(this.#used < LENGTH_START ? BLOCK_SIZE : 2 * BLOCK_SIZE);
    trailer.set(this.#tail.subarray(0, this.#used));
    trailer[this.#used] = 0x80;
    const padding = new DataView(trailer.buffer);
    const bitLength = this.#length << 3n;
    padding.setBigUint64(trailer.length - 16, bitLength >> 64n);
    padding.setBigUint64(trailer.length - 8, bitLength & MASK64);
    const schedule = new Uint32Array(32);
    for (let offset = 0; offset < trailer.length; offset += BLOCK_SIZE) {
      compress(state, padding, offset, schedule);
    }
    const output = new Uint8Array(64);
    const view = new DataView(output.buffer);
    for (let i = 0; i < state.length; i += 1) view.setUint32(4 * i, state[i]);
    return output;
  }
}

export function sha512(input: Uint8Array): Uint8Array {
  return new Sha512().update(input).digest();
}
