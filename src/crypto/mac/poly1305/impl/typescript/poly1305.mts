// RFC 8439 Poly1305 with ten 13-bit limbs and fixed-schedule Number arithmetic.
import { asUint8Array } from '../../../../inputs/bytes.mts';

const BLOCK_BYTES = 16;
const LIMBS = 10;
const RADIX = 8192;
const MASK = RADIX - 1;

function decode(bytes: Uint8Array, offset: number, size: number, blockMarker: boolean, out: Uint32Array) {
  out.fill(0);
  for (let i = 0; i < size; i += 1) {
    const bit = i * 8;
    const limb = Math.floor(bit / 13);
    const shift = bit % 13;
    const byte = bytes[offset + i];
    out[limb] |= (byte << shift) & MASK;
    if (shift > 5) out[limb + 1] |= byte >>> (13 - shift);
  }
  if (blockMarker) {
    const highBit = size * 8;
    out[Math.floor(highBit / 13)] |= 1 << (highBit % 13);
  }
}

function absorb(
  h: Uint32Array, keyWindow: Uint32Array, bytes: Uint8Array, offset: number, size: number,
  scratch: Float64Array, digits: Uint32Array,
) {
  decode(bytes, offset, size, true, digits);
  for (let i = 0; i < LIMBS; i += 1) digits[i] += h[i];
  // Each column reads ten positions. The wrapped positions already include the factor of 5.
  for (let column = 0; column < LIMBS; column += 1) {
    const last = column + LIMBS - 1;
    let sum = 0;
    for (let input = 0; input < LIMBS; input += 1) {
      sum += digits[input] * keyWindow[last - input];
    }
    scratch[column] = sum;
  }
  for (let pass = 0; pass < 3; pass += 1) {
    for (let i = 0; i < LIMBS - 1; i += 1) {
      const carry = Math.floor(scratch[i] / RADIX);
      scratch[i] -= carry * RADIX;
      scratch[i + 1] += carry;
    }
    const carry = Math.floor(scratch[LIMBS - 1] / RADIX);
    scratch[LIMBS - 1] -= carry * RADIX;
    scratch[0] += 5 * carry;
  }
  h.set(scratch);
}

function serialize(h: Uint32Array, pad: Uint8Array, candidate: Uint32Array) {
  let carry = 5;
  for (let i = 0; i < LIMBS; i += 1) {
    const total = h[i] + carry;
    candidate[i] = total & MASK;
    carry = total >>> 13;
  }
  const select = -carry;
  for (let i = 0; i < LIMBS; i += 1) h[i] ^= select & (h[i] ^ candidate[i]);
  const tag = new Uint8Array(BLOCK_BYTES);
  carry = 0;
  for (let i = 0; i < BLOCK_BYTES; i += 1) {
    const bit = i * 8;
    const limb = Math.floor(bit / 13);
    const shift = bit % 13;
    let word = h[limb] >>> shift;
    if (shift > 5) word |= h[limb + 1] << (13 - shift);
    const total = (word & 255) + pad[i] + carry;
    tag[i] = total;
    carry = total >>> 8;
  }
  return tag;
}

export class Poly1305 {
  #keyWindow = new Uint32Array(2 * LIMBS - 1);
  #h = new Uint32Array(LIMBS);
  #scratch = new Float64Array(LIMBS);
  #digits = new Uint32Array(LIMBS);
  #pending = new Uint8Array(BLOCK_BYTES);
  #pad: Uint8Array;
  #used = 0;
  #hasInput = false;

  constructor(key: Uint8Array) {
    const bytes = asUint8Array(key);
    if (bytes.length !== 32) throw new RangeError('Poly1305 requires a 32-byte one-time key');
    const clipped = bytes.slice(0, 16);
    for (let i = 3; i < 16; i += 4) clipped[i] &= 15;
    for (let i = 4; i < 16; i += 4) clipped[i] &= 252;
    // Store [5*r1, …, 5*r9, r0, …, r9] for the folded radix-2^13 convolution.
    const limbs = this.#keyWindow.subarray(LIMBS - 1);
    decode(clipped, 0, 16, false, limbs);
    for (let i = 1; i < LIMBS; i += 1) this.#keyWindow[i - 1] = 5 * limbs[i];
    this.#pad = bytes.slice(16);
    clipped.fill(0);
  }

  update(input: Uint8Array) {
    const bytes = asUint8Array(input);
    if (bytes.length === 0) return this;
    this.#hasInput = true;
    let offset = 0;
    if (this.#used > 0) {
      offset = Math.min(BLOCK_BYTES - this.#used, bytes.length);
      this.#pending.set(bytes.subarray(0, offset), this.#used);
      this.#used += offset;
      if (this.#used < BLOCK_BYTES) return this;
      absorb(this.#h, this.#keyWindow, this.#pending, 0, BLOCK_BYTES, this.#scratch, this.#digits);
    }
    while (bytes.length - offset >= BLOCK_BYTES) {
      absorb(this.#h, this.#keyWindow, bytes, offset, BLOCK_BYTES, this.#scratch, this.#digits);
      offset += BLOCK_BYTES;
    }
    this.#pending.set(bytes.subarray(offset));
    this.#used = bytes.length - offset;
    return this;
  }

  // Passing a snapshot to an adversary counts as using the one-time key.
  digest() {
    if (!this.#hasInput) return this.#pad.slice();
    const h = this.#h.slice();
    if (this.#used > 0) {
      absorb(h, this.#keyWindow, this.#pending, 0, this.#used, this.#scratch, this.#digits);
    }
    return serialize(h, this.#pad, this.#digits);
  }
}

export function authenticate(key: Uint8Array, message: Uint8Array) {
  return new Poly1305(key).update(message).digest();
}
