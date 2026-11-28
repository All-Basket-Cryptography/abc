import { asUint8Array } from '../../../../inputs/bytes.mts';

// Table-free AES-256 for one-block encrypt/decrypt (FIPS 197).
const KEY_BYTES = 32;
const BLOCK_BYTES = 16;
const ROUNDS = 14;

function xtime(value: number) {
  return ((value << 1) & 255) ^ (0x1b & -(value >>> 7));
}

function multiply(left: number, right: number) {
  let result = 0;
  for (let bit = 0; bit < 8; bit += 1) {
    result ^= left & -(right & 1);
    left = xtime(left);
    right >>>= 1;
  }
  return result;
}

function square(value: number) {
  let spread = (value | (value << 4)) & 0x0f0f;
  spread = (spread | (spread << 2)) & 0x3333;
  spread = (spread | (spread << 1)) & 0x5555;
  let high = spread >>> 8;
  const folded = (spread & 255) ^ high ^ (high << 1) ^ (high << 3) ^ (high << 4);
  high = folded >>> 8;
  return (folded ^ high ^ (high << 1) ^ (high << 3) ^ (high << 4)) & 255;
}

function inverse(value: number) {
  const x2 = square(value);
  const x3 = multiply(x2, value);
  const x7 = multiply(square(x3), value);
  const x15 = multiply(square(x7), value);
  const x120 = square(square(square(x15)));
  return square(multiply(x120, x7));
}

function rotate(value: number, amount: number) {
  return ((value << amount) | (value >>> (8 - amount))) & 255;
}

function substitute(value: number) {
  const x = inverse(value);
  return x ^ rotate(x, 1) ^ rotate(x, 2) ^ rotate(x, 3) ^ rotate(x, 4) ^ 0x63;
}

function inverseSubstitute(value: number) {
  return inverse(rotate(value, 1) ^ rotate(value, 3) ^ rotate(value, 6) ^ 5);
}

function expand(key: Uint8Array) {
  const expanded = new Uint8Array(BLOCK_BYTES * (ROUNDS + 1));
  expanded.set(key);
  let rcon = 1;
  for (let offset = KEY_BYTES; offset < expanded.length; offset += 4) {
    let a = expanded[offset - 4], b = expanded[offset - 3];
    let c = expanded[offset - 2], d = expanded[offset - 1];
    if (offset % 32 === 0) {
      const first = a;
      a = substitute(b) ^ rcon;
      b = substitute(c);
      c = substitute(d);
      d = substitute(first);
      rcon = xtime(rcon);
    } else if (offset % 32 === 16) {
      a = substitute(a);
      b = substitute(b);
      c = substitute(c);
      d = substitute(d);
    }
    expanded[offset] = expanded[offset - 32] ^ a;
    expanded[offset + 1] = expanded[offset - 31] ^ b;
    expanded[offset + 2] = expanded[offset - 30] ^ c;
    expanded[offset + 3] = expanded[offset - 29] ^ d;
  }
  return expanded;
}

function addKey(state: Uint8Array, key: Uint8Array, round: number) {
  const position = round * BLOCK_BYTES;
  for (let i = 0; i < BLOCK_BYTES; i += 1) state[i] ^= key[position + i];
}

function shiftRows(state: Uint8Array, direction: number) {
  for (let row = 1; row <= 3; row += 1) {
    const a = row, b = row + 4, c = row + 8, d = row + 12;
    const shift = (direction * row) & 3;
    const first = state[a];
    if (shift === 1) {
      state[a] = state[b];
      state[b] = state[c];
      state[c] = state[d];
      state[d] = first;
    } else if (shift === 2) {
      const second = state[b];
      state[a] = state[c];
      state[b] = state[d];
      state[c] = first;
      state[d] = second;
    } else {
      state[a] = state[d];
      state[d] = state[c];
      state[c] = state[b];
      state[b] = first;
    }
  }
}

function mixColumns(state: Uint8Array, undo: boolean) {
  for (let i = 0; i < BLOCK_BYTES; i += 4) {
    let a = state[i], b = state[i + 1], c = state[i + 2], d = state[i + 3];
    if (undo) {
      const even = xtime(xtime(a ^ c)), odd = xtime(xtime(b ^ d));
      a ^= even;
      b ^= odd;
      c ^= even;
      d ^= odd;
    }
    const total = a ^ b ^ c ^ d;
    state[i] = a ^ total ^ xtime(a ^ b);
    state[i + 1] = b ^ total ^ xtime(b ^ c);
    state[i + 2] = c ^ total ^ xtime(c ^ d);
    state[i + 3] = d ^ total ^ xtime(d ^ a);
  }
}

export class Aes256 {
  #roundKeys: Uint8Array;

  constructor(key: Uint8Array) {
    const bytes = asUint8Array(key);
    if (bytes.length !== KEY_BYTES) throw new RangeError('AES-256 requires a 32-byte key');
    this.#roundKeys = expand(bytes);
  }

  encrypt(block: Uint8Array) {
    const bytes = asUint8Array(block);
    if (bytes.length !== BLOCK_BYTES) throw new RangeError('AES-256 requires a 16-byte block');
    const state = new Uint8Array(bytes);
    addKey(state, this.#roundKeys, 0);
    for (let round = 1; round <= ROUNDS; round += 1) {
      for (let i = 0; i < BLOCK_BYTES; i += 1) state[i] = substitute(state[i]);
      shiftRows(state, 1);
      if (round !== ROUNDS) mixColumns(state, false);
      addKey(state, this.#roundKeys, round);
    }
    return state;
  }

  decrypt(block: Uint8Array) {
    const bytes = asUint8Array(block);
    if (bytes.length !== BLOCK_BYTES) throw new RangeError('AES-256 requires a 16-byte block');
    const state = new Uint8Array(bytes);
    addKey(state, this.#roundKeys, ROUNDS);
    for (let round = ROUNDS - 1; round >= 0; round -= 1) {
      shiftRows(state, 3);
      for (let i = 0; i < BLOCK_BYTES; i += 1) state[i] = inverseSubstitute(state[i]);
      addKey(state, this.#roundKeys, round);
      if (round !== 0) mixColumns(state, true);
    }
    return state;
  }
}
