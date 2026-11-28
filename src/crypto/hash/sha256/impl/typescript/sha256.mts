import { asUint8Array } from '../../../../inputs/bytes.mts';

/** Byte-oriented FIPS 180-4 SHA-256 with an expanded message schedule. */
const bytesPerBlock = 64;
export const MAX_MESSAGE_BYTES = (1n << 61n) - 1n;

const initialWords = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
] as const;

const roundWords = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
] as const;

function ror(word: number, distance: number): number {
  return (word >>> distance) | (word << (32 - distance));
}

function wordSchedule(input: DataView, offset: number, words: Uint32Array): void {
  for (let i = 0; i < 16; ++i) words[i] = input.getUint32(offset + i * 4, false);
  for (let i = 16; i < words.length; ++i) {
    const earlier = words[i - 15];
    const later = words[i - 2];
    const sigma0 = ror(earlier, 7) ^ ror(earlier, 18) ^ (earlier >>> 3);
    const sigma1 = ror(later, 17) ^ ror(later, 19) ^ (later >>> 10);
    words[i] = words[i - 16] + words[i - 7] + sigma0 + sigma1;
  }
}

function absorbBlock(chaining: Uint32Array, input: DataView, offset: number, words: Uint32Array): void {
  wordSchedule(input, offset, words);
  let a = chaining[0], b = chaining[1], c = chaining[2], d = chaining[3];
  let e = chaining[4], f = chaining[5], g = chaining[6], h = chaining[7];
  for (let round = 0; round < roundWords.length; ++round) {
    const sigma0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
    const sigma1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
    const choose = (e & f) | (~e & g);
    const majority = (a & b) ^ (a & c) ^ (b & c);
    const first = h + sigma1 + choose + roundWords[round] + words[round];
    h = g; g = f; f = e; e = (d + first) >>> 0;
    d = c; c = b; b = a; a = (first + sigma0 + majority) >>> 0;
  }
  chaining[0] += a; chaining[1] += b; chaining[2] += c; chaining[3] += d;
  chaining[4] += e; chaining[5] += f; chaining[6] += g; chaining[7] += h;
}

function byteView(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function digestScratch() {
  const bytes = new Uint8Array(2 * bytesPerBlock);
  return { state: new Uint32Array(8), bytes, view: byteView(bytes) };
}

export class Sha256 {
  #chaining = Uint32Array.from(initialWords);
  #pending = new Uint8Array(bytesPerBlock);
  #pendingView = byteView(this.#pending);
  #used = 0;
  #length = 0n;
  #schedule = new Uint32Array(64);
  #digestScratch?: ReturnType<typeof digestScratch>;

  reset(): void {
    this.#chaining.set(initialWords);
    this.#pending.fill(0, 0, this.#used);
    this.#used = 0;
    this.#length = 0n;
  }

  /** Restore an independent copy of a prefix state. */
  copyFrom(source: Sha256): this {
    const used = source.#used;
    this.#chaining.set(source.#chaining);
    if (used > 0) this.#pending.set(source.#pending.subarray(0, used));
    if (used < this.#used) this.#pending.fill(0, used, this.#used);
    this.#used = used;
    this.#length = source.#length;
    return this;
  }

  update(bytes: Uint8Array): this {
    bytes = asUint8Array(bytes);
    const total = this.#length + BigInt(bytes.byteLength);
    if (total > MAX_MESSAGE_BYTES) throw new RangeError('SHA-256 input exceeds the bit-length domain');
    if (bytes.byteLength === 0) return this;
    this.#length = total;

    let consumed = 0;
    if (this.#used > 0) {
      consumed = Math.min(bytesPerBlock - this.#used, bytes.byteLength);
      this.#pending.set(bytes.subarray(0, consumed), this.#used);
      this.#used += consumed;
      if (this.#used < bytesPerBlock) return this;
      absorbBlock(this.#chaining, this.#pendingView, 0, this.#schedule);
    }

    if (consumed + bytesPerBlock <= bytes.byteLength) {
      const input = byteView(bytes);
      for (; consumed + bytesPerBlock <= input.byteLength; consumed += bytesPerBlock) {
        absorbBlock(this.#chaining, input, consumed, this.#schedule);
      }
    }
    this.#pending.set(bytes.subarray(consumed));
    this.#used = bytes.byteLength - consumed;
    return this;
  }

  digest(): Uint8Array {
    const { state, bytes, view } = this.#digestScratch ??= digestScratch();
    state.set(this.#chaining);
    const paddedLength = this.#used < 56 ? bytesPerBlock : 2 * bytesPerBlock;
    bytes.fill(0, this.#used, paddedLength);
    bytes.set(this.#pending.subarray(0, this.#used));
    bytes[this.#used] = 0x80;
    view.setBigUint64(paddedLength - 8, this.#length << 3n, false);
    for (let offset = 0; offset < paddedLength; offset += bytesPerBlock) {
      absorbBlock(state, view, offset, this.#schedule);
    }

    const digest = new Uint8Array(32);
    const output = byteView(digest);
    for (let i = 0; i < state.length; ++i) output.setUint32(i * 4, state[i], false);
    bytes.fill(0, 0, paddedLength);
    return digest;
  }
}

export function sha256(bytes: Uint8Array): Uint8Array {
  return new Sha256().update(bytes).digest();
}
