import { asUint8Array } from '../../../../inputs/bytes.mts';

/** Byte-oriented FIPS 180-4 SHA-256 with a rotating working register index. */
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

function wordSchedule(input: DataView, offset: number): Uint32Array {
  const words = new Uint32Array(64);
  for (let i = 0; i < 16; ++i) words[i] = input.getUint32(offset + i * 4, false);
  for (let i = 16; i < words.length; ++i) {
    const earlier = words[i - 15];
    const later = words[i - 2];
    const sigma0 = ror(earlier, 7) ^ ror(earlier, 18) ^ (earlier >>> 3);
    const sigma1 = ror(later, 17) ^ ror(later, 19) ^ (later >>> 10);
    words[i] = words[i - 16] + words[i - 7] + sigma0 + sigma1;
  }
  return words;
}

function absorbBlock(chaining: Uint32Array, input: DataView, offset: number): void {
  const words = wordSchedule(input, offset);
  const working = chaining.slice();
  let head = 0;
  for (let round = 0; round < roundWords.length; ++round) {
    const a = working[head];
    const b = working[(head + 1) & 7];
    const c = working[(head + 2) & 7];
    const d = (head + 3) & 7;
    const e = working[(head + 4) & 7];
    const f = working[(head + 5) & 7];
    const g = working[(head + 6) & 7];
    const nextHead = (head + 7) & 7;
    const sigma0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
    const sigma1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
    const choose = (e & f) | (~e & g);
    const majority = (a & b) ^ (a & c) ^ (b & c);
    const first = working[nextHead] + sigma1 + choose + roundWords[round] + words[round];
    // Moving the head rotates six words. The retired h and d slots receive a′ and e′.
    working[nextHead] = first + sigma0 + majority;
    working[d] += first;
    head = nextHead;
  }
  for (let i = 0; i < chaining.length; ++i) chaining[i] += working[(head + i) & 7];
}

function byteView(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export class Sha256 {
  #chaining = Uint32Array.from(initialWords);
  #pending: Uint8Array = new Uint8Array(0);
  #length = 0n;

  reset(): void {
    this.#chaining.set(initialWords);
    this.#pending = new Uint8Array(0);
    this.#length = 0n;
  }

  update(bytes: Uint8Array): this {
    bytes = asUint8Array(bytes);
    const total = this.#length + BigInt(bytes.byteLength);
    if (total > MAX_MESSAGE_BYTES) throw new RangeError('SHA-256 input exceeds the bit-length domain');
    if (bytes.byteLength === 0) return this;
    this.#length = total;

    let consumed = 0;
    if (this.#pending.length > 0) {
      consumed = Math.min(bytesPerBlock - this.#pending.length, bytes.byteLength);
      const head = new Uint8Array(this.#pending.length + consumed);
      head.set(this.#pending);
      head.set(bytes.subarray(0, consumed), this.#pending.length);
      if (head.length < bytesPerBlock) {
        this.#pending = head;
        return this;
      }
      absorbBlock(this.#chaining, byteView(head), 0);
    }

    const input = byteView(bytes);
    for (; consumed + bytesPerBlock <= input.byteLength; consumed += bytesPerBlock) {
      absorbBlock(this.#chaining, input, consumed);
    }
    this.#pending = Uint8Array.from(bytes.subarray(consumed));
    return this;
  }

  digest(): Uint8Array {
    const state = this.#chaining.slice();
    const count = this.#pending.length;
    const tail = new Uint8Array(Math.ceil((count + 9) / bytesPerBlock) * bytesPerBlock);
    tail.set(this.#pending);
    tail[count] = 0x80;
    let bitLength = this.#length << 3n;
    for (let i = tail.length - 1; i >= tail.length - 8; --i) {
      tail[i] = Number(bitLength & 255n);
      bitLength >>= 8n;
    }
    const padding = byteView(tail);
    for (let offset = 0; offset < tail.length; offset += bytesPerBlock) absorbBlock(state, padding, offset);

    const digest = byteView(new Uint8Array(32));
    for (let i = 0; i < state.length; ++i) digest.setUint32(i * 4, state[i], false);
    return new Uint8Array(digest.buffer);
  }
}

export function sha256(bytes: Uint8Array): Uint8Array {
  return new Sha256().update(bytes).digest();
}
