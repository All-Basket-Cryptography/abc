// RFC 8439 Poly1305 with ten 13-bit limbs and fixed-schedule Number arithmetic.
import { asUint8Array } from '../../../../inputs/bytes.mjs';

const BLOCK_BYTES = 16;
const LIMBS = 10;
const RADIX = 8192;
const MASK = RADIX - 1;

function decode(bytes, size, blockMarker, out) {
  out.fill(0);
  for (let i = 0; i < size; i += 1) {
    const bit = i * 8;
    const limb = Math.floor(bit / 13);
    const shift = bit % 13;
    out[limb] |= (bytes[i] << shift) & MASK;
    if (shift > 5) out[limb + 1] |= bytes[i] >>> (13 - shift);
  }
  if (blockMarker) {
    const highBit = size * 8;
    out[Math.floor(highBit / 13)] |= 1 << (highBit % 13);
  }
}

function absorb(
  h, r, bytes, size,
  scratch, digits,
) {
  decode(bytes, size, true, digits);
  for (let i = 0; i < LIMBS; i += 1) digits[i] += h[i];
  // x^10 = 5 (mod 2^130 - 5), with x = 2^13.
  scratch.fill(0);
  for (let i = 0; i < LIMBS; i += 1) {
    for (let j = 0; j < LIMBS; j += 1) {
      const index = i + j;
      const term = digits[i] * r[j];
      if (index < LIMBS) scratch[index] += term;
      else scratch[index - LIMBS] += 5 * term;
    }
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

function serialize(h, pad) {
  const candidate = new Uint32Array(LIMBS);
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
  #r = new Uint32Array(LIMBS);
  #h = new Uint32Array(LIMBS);
  #scratch = new Float64Array(LIMBS);
  #digits = new Uint32Array(LIMBS);
  #pending = new Uint8Array(BLOCK_BYTES);
  #pad;
  #used = 0;

  constructor(key) {
    const bytes = asUint8Array(key);
    if (bytes.length !== 32) throw new RangeError('Poly1305 requires a 32-byte one-time key');
    const clipped = Uint8Array.from(bytes.subarray(0, 16));
    for (const i of [3, 7, 11, 15]) clipped[i] &= 15;
    for (const i of [4, 8, 12]) clipped[i] &= 252;
    decode(clipped, 16, false, this.#r);
    this.#pad = Uint8Array.from(bytes.subarray(16));
    clipped.fill(0);
  }

  update(input) {
    const bytes = asUint8Array(input);
    let offset = 0;
    if (this.#used > 0) {
      offset = Math.min(BLOCK_BYTES - this.#used, bytes.length);
      this.#pending.set(bytes.subarray(0, offset), this.#used);
      this.#used += offset;
      if (this.#used < BLOCK_BYTES) return this;
      absorb(this.#h, this.#r, this.#pending, BLOCK_BYTES, this.#scratch, this.#digits);
    }
    while (bytes.length - offset >= BLOCK_BYTES) {
      absorb(this.#h, this.#r, bytes.subarray(offset, offset + BLOCK_BYTES),
        BLOCK_BYTES, this.#scratch, this.#digits);
      offset += BLOCK_BYTES;
    }
    this.#pending.set(bytes.subarray(offset));
    this.#used = bytes.length - offset;
    return this;
  }

  // Passing a snapshot to an adversary counts as using the one-time key.
  digest() {
    const h = this.#h.slice();
    if (this.#used > 0) {
      absorb(h, this.#r, this.#pending, this.#used, this.#scratch, this.#digits);
    }
    return serialize(h, this.#pad);
  }
}

export function authenticate(key, message) {
  return new Poly1305(key).update(message).digest();
}
