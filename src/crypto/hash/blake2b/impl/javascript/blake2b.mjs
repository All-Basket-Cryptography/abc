// RFC 7693 sequential, unkeyed BLAKE2b. Each word has low and high 32-bit halves.
const BLOCK_BYTES = 128;
const BYTE_LIMIT = 1n << 128n;
const IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);
const SIGMA = new Uint8Array([
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
  14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3,
  11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4,
  7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8,
  9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13,
  2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9,
  12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11,
  13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10,
  6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5,
  10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0,
]);

function mix(v, m, a, b, c, d, x, y) {
  let al = v[a], ah = v[a + 1];
  let bl = v[b], bh = v[b + 1];
  let cl = v[c], ch = v[c + 1];
  let dl = v[d], dh = v[d + 1];

  let sum = al + bl + m[x];
  al = sum >>> 0;
  ah = (ah + bh + m[x + 1] + Math.floor(sum / 0x100000000)) >>> 0;
  let lo = dl ^ al, hi = dh ^ ah;
  dl = hi >>> 0;
  dh = lo >>> 0;

  sum = cl + dl;
  cl = sum >>> 0;
  ch = (ch + dh + Number(sum >= 0x100000000)) >>> 0;
  lo = bl ^ cl;
  hi = bh ^ ch;
  bl = ((lo >>> 24) | (hi << 8)) >>> 0;
  bh = ((hi >>> 24) | (lo << 8)) >>> 0;

  sum = al + bl + m[y];
  al = sum >>> 0;
  ah = (ah + bh + m[y + 1] + Math.floor(sum / 0x100000000)) >>> 0;
  lo = dl ^ al;
  hi = dh ^ ah;
  dl = ((lo >>> 16) | (hi << 16)) >>> 0;
  dh = ((hi >>> 16) | (lo << 16)) >>> 0;

  sum = cl + dl;
  cl = sum >>> 0;
  ch = (ch + dh + Number(sum >= 0x100000000)) >>> 0;
  lo = bl ^ cl;
  hi = bh ^ ch;
  bl = (lo << 1) | (hi >>> 31);
  bh = (hi << 1) | (lo >>> 31);

  v[a] = al;
  v[a + 1] = ah;
  v[b] = bl;
  v[b + 1] = bh;
  v[c] = cl;
  v[c + 1] = ch;
  v[d] = dl;
  v[d + 1] = dh;
}

function compress(state, message, work, bytes, offset, count, final) {
  for (let i = 0; i < 32; i += 1) message[i] = bytes.getUint32(offset + i * 4, true);
  work.set(state);
  work.set(IV, 16);
  for (let i = 0; i < 4; i += 1) {
    work[24 + i] ^= Number(count & 0xffffffffn);
    count >>= 32n;
  }
  if (final) {
    work[28] ^= 0xffffffff;
    work[29] ^= 0xffffffff;
  }
  for (let round = 0; round < 12; round += 1) {
    const s = (round % 10) * 16;
    mix(work, message, 0, 8, 16, 24, 2 * SIGMA[s], 2 * SIGMA[s + 1]);
    mix(work, message, 2, 10, 18, 26, 2 * SIGMA[s + 2], 2 * SIGMA[s + 3]);
    mix(work, message, 4, 12, 20, 28, 2 * SIGMA[s + 4], 2 * SIGMA[s + 5]);
    mix(work, message, 6, 14, 22, 30, 2 * SIGMA[s + 6], 2 * SIGMA[s + 7]);
    mix(work, message, 0, 10, 20, 30, 2 * SIGMA[s + 8], 2 * SIGMA[s + 9]);
    mix(work, message, 2, 12, 22, 24, 2 * SIGMA[s + 10], 2 * SIGMA[s + 11]);
    mix(work, message, 4, 14, 16, 26, 2 * SIGMA[s + 12], 2 * SIGMA[s + 13]);
    mix(work, message, 6, 8, 18, 28, 2 * SIGMA[s + 14], 2 * SIGMA[s + 15]);
  }
  for (let i = 0; i < 16; i += 1) state[i] ^= work[i] ^ work[16 + i];
}

export class Blake2b {
  #state = IV.slice();
  #message = new Uint32Array(32);
  #work = new Uint32Array(32);
  #pending = new Uint8Array(BLOCK_BYTES);
  #pendingView = new DataView(this.#pending.buffer);
  #processed = 0n;
  #used = 0;
  #length;

  constructor(length = 64) {
    if (!Number.isInteger(length) || length < 1 || length > 64) {
      throw new RangeError('BLAKE2b requires a digest length from 1 through 64 bytes');
    }
    this.#length = length;
    this.#state[0] ^= 0x01010000 | length;
  }

  #absorb(view, offset) {
    this.#processed += BigInt(BLOCK_BYTES);
    compress(this.#state, this.#message, this.#work, view, offset, this.#processed, false);
  }

  update(input) {
    if (!(input instanceof Uint8Array) || !(input.buffer instanceof ArrayBuffer)) {
      throw new TypeError('BLAKE2b requires Uint8Array backed by an ArrayBuffer');
    }
    const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
    if (this.#processed + BigInt(this.#used) + BigInt(view.byteLength) >= BYTE_LIMIT) {
      throw new RangeError('BLAKE2b byte counter would wrap');
    }
    if (view.byteLength === 0) return this;
    let offset = 0;
    if (this.#used !== 0) {
      offset = Math.min(BLOCK_BYTES - this.#used, view.byteLength);
      this.#pending.set(input.subarray(0, offset), this.#used);
      this.#used += offset;
      if (offset === view.byteLength) return this;
      this.#absorb(this.#pendingView, 0);
    }
    while (view.byteLength - offset > BLOCK_BYTES) {
      this.#absorb(view, offset);
      offset += BLOCK_BYTES;
    }
    this.#pending.set(input.subarray(offset));
    this.#used = view.byteLength - offset;
    return this;
  }

  digest() {
    const result = this.#state.slice();
    const tail = this.#pending.slice(0, BLOCK_BYTES);
    tail.fill(0, this.#used);
    compress(result, this.#message, this.#work, new DataView(tail.buffer), 0,
      this.#processed + BigInt(this.#used), true);
    const digest = new Uint8Array(this.#length);
    for (let i = 0; i < this.#length; i += 1) digest[i] = result[i >>> 2] >>> ((i & 3) * 8);
    return digest;
  }
}

export function blake2b(input, length = 64) {
  return new Blake2b(length).update(input).digest();
}
