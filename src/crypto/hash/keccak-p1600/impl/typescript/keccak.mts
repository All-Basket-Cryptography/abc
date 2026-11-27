// FIPS 202 Keccak-p[1600,24] in low/high 32-bit words, lane x + 5*y.
export const RATE = 136;
const ROTATION = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];
const PI = [
  0, 10, 20, 5, 15,
  16, 1, 11, 21, 6,
  7, 17, 2, 12, 22,
  23, 8, 18, 3, 13,
  14, 24, 9, 19, 4,
];
const ROUND_CONSTANTS = Uint32Array.of(
  0x00000001, 0x00000000, 0x00008082, 0x00000000, 0x0000808a, 0x80000000,
  0x80008000, 0x80000000, 0x0000808b, 0x00000000, 0x80000001, 0x00000000,
  0x80008081, 0x80000000, 0x00008009, 0x80000000, 0x0000008a, 0x00000000,
  0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a, 0x00000000,
  0x8000808b, 0x00000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000,
  0x00008003, 0x80000000, 0x00008002, 0x80000000, 0x00000080, 0x80000000,
  0x0000800a, 0x00000000, 0x8000000a, 0x80000000, 0x80008081, 0x80000000,
  0x00008080, 0x80000000, 0x80000001, 0x00000000, 0x80008008, 0x80000000,
);

function rotateInto(target: Uint32Array, index: number, low: number, high: number, count: number) {
  if (count >= 32) {
    const swap = low;
    low = high;
    high = swap;
    count -= 32;
  }
  if (count === 0) {
    target[index] = low;
    target[index + 1] = high;
  } else {
    target[index] = (low << count) | (high >>> (32 - count));
    target[index + 1] = (high << count) | (low >>> (32 - count));
  }
}

export function permute(lanes: Uint32Array) {
  if (!(lanes instanceof Uint32Array) || lanes.length !== 50) throw new TypeError('Keccak requires 50 limbs');
  const moved = new Uint32Array(50);
  const parity = new Uint32Array(10);
  const theta = new Uint32Array(10);
  for (let round = 0; round < 48; round += 2) {
    for (let i = 0; i < 10; i += 1) {
      parity[i] = lanes[i] ^ lanes[i + 10] ^ lanes[i + 20] ^ lanes[i + 30] ^ lanes[i + 40];
    }
    for (let i = 0; i < 10; i += 2) {
      const previous = (i + 8) % 10;
      const next = (i + 2) % 10;
      theta[i] = parity[previous] ^ (parity[next] << 1) ^ (parity[next + 1] >>> 31);
      theta[i + 1] = parity[previous + 1] ^ (parity[next + 1] << 1) ^ (parity[next] >>> 31);
    }
    for (let row = 0; row < 50; row += 10) {
      for (let i = 0; i < 10; i += 2) {
        const index = row + i;
        const lane = index >>> 1;
        rotateInto(moved, 2 * PI[lane], lanes[index] ^ theta[i],
          lanes[index + 1] ^ theta[i + 1], ROTATION[lane]);
      }
    }
    for (let row = 0; row < 50; row += 10) {
      for (let i = 0; i < 10; i += 1) {
        lanes[row + i] = moved[row + i] ^ (~moved[row + (i + 2) % 10] & moved[row + (i + 4) % 10]);
      }
    }
    lanes[0] ^= ROUND_CONSTANTS[round];
    lanes[1] ^= ROUND_CONSTANTS[round + 1];
  }
}

function absorb(state: Uint32Array, input: DataView, offset: number) {
  for (let i = 0; i < RATE / 4; i += 1) state[i] ^= input.getUint32(offset + 4 * i, true);
  permute(state);
}

function inputView(bytes: Uint8Array) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('Keccak requires a Uint8Array');
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export class Sponge {
  #state = new Uint32Array(50);
  #tail = new Uint8Array(RATE);
  #used = 0;

  update(input: Uint8Array) {
    const view = inputView(input);
    let offset = 0;
    if (this.#used !== 0) {
      offset = Math.min(input.length, RATE - this.#used);
      this.#tail.set(input.subarray(0, offset), this.#used);
      this.#used += offset;
      if (this.#used < RATE) return;
      absorb(this.#state, inputView(this.#tail), 0);
    }
    while (input.length - offset >= RATE) {
      absorb(this.#state, view, offset);
      offset += RATE;
    }
    this.#tail.set(input.subarray(offset));
    this.#used = input.length - offset;
  }

  reader(domain: 0x06 | 0x1f) {
    if (domain !== 0x06 && domain !== 0x1f) throw new RangeError('Unsupported Keccak domain');
    const state = this.#state.slice();
    const final = new Uint8Array(RATE);
    final.set(this.#tail.subarray(0, this.#used));
    final[this.#used] = domain;
    final[RATE - 1] |= 0x80;
    absorb(state, inputView(final), 0);
    return new Reader(state);
  }
}

class Reader {
  #state: Uint32Array;
  #encoded = new Uint8Array(RATE);
  #cursor = 0;

  constructor(state: Uint32Array) {
    this.#state = state;
    this.#encode();
  }

  #encode() {
    const output = inputView(this.#encoded);
    for (let i = 0; i < RATE / 4; i += 1) output.setUint32(4 * i, this.#state[i], true);
  }

  readInto(output: Uint8Array) {
    inputView(output);
    for (let offset = 0; offset < output.length;) {
      if (this.#cursor === RATE) {
        permute(this.#state);
        this.#encode();
        this.#cursor = 0;
      }
      const count = Math.min(RATE - this.#cursor, output.length - offset);
      output.set(this.#encoded.subarray(this.#cursor, this.#cursor + count), offset);
      this.#cursor += count;
      offset += count;
    }
    return output.length;
  }

  read(size: number) {
    if (!Number.isSafeInteger(size) || size < 0) throw new RangeError('Invalid SHAKE output length');
    const result = new Uint8Array(size);
    this.readInto(result);
    return result;
  }
}
