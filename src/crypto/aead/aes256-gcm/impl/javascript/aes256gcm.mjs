import { asUint8Array } from '../../../../inputs/bytes.mjs';
import { Aes256 } from '../../../../cipher/aes256/impl/javascript/aes256.mjs';

// NIST SP 800-38D: a 96-bit nonce and detached 128-bit tag.
const BLOCK_BYTES = 16;
const MAX_MESSAGE = (0xffffffff - 1) * BLOCK_BYTES;
const MAX_AAD = (1n << 61n) - 1n;

function multiply(accumulator, key) {
  let a = key[0], b = key[1], c = key[2], d = key[3];
  let x = 0, y = 0, z = 0, w = 0;
  for (let lane = 0; lane < 4; lane += 1) {
    const word = accumulator[lane];
    for (let bit = 31; bit >= 0; bit -= 1) {
      const mask = -((word >>> bit) & 1);
      x ^= a & mask;
      y ^= b & mask;
      z ^= c & mask;
      w ^= d & mask;
      const reduction = -(d & 1);
      d = (d >>> 1) | (c << 31);
      c = (c >>> 1) | (b << 31);
      b = (b >>> 1) | (a << 31);
      a = (a >>> 1) ^ (0xe1000000 & reduction);
    }
  }
  accumulator[0] = x;
  accumulator[1] = y;
  accumulator[2] = z;
  accumulator[3] = w;
}

function makeView(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function append(accumulator, key, data) {
  const view = makeView(data);
  let offset = 0;
  while (data.length - offset >= BLOCK_BYTES) {
    for (let i = 0; i < 4; i += 1) accumulator[i] ^= view.getUint32(offset + i * 4);
    multiply(accumulator, key);
    offset += BLOCK_BYTES;
  }
  if (offset < data.length) {
    for (let i = 0; i < data.length - offset; i += 1) {
      accumulator[i >>> 2] ^= data[offset + i] << (24 - (i & 3) * 8);
    }
    multiply(accumulator, key);
  }
}

function initialCounter(nonce) {
  if (nonce.length !== 12) throw new RangeError('AES-256-GCM requires a 12-byte nonce');
  const bytes = new Uint8Array(BLOCK_BYTES);
  bytes.set(nonce);
  bytes[15] = 1;
  return bytes;
}

function applyPayload(aes, counter, payload) {
  const words = makeView(counter);
  const output = new Uint8Array(payload.length);
  for (let offset = 0; offset < payload.length; offset += BLOCK_BYTES) {
    words.setUint32(12, 2 + offset / BLOCK_BYTES);
    const pad = aes.encrypt(counter);
    const size = Math.min(BLOCK_BYTES, payload.length - offset);
    for (let i = 0; i < size; i += 1) output[offset + i] = payload[offset + i] ^ pad[i];
  }
  return output;
}

function authenticate(aes, counter, aad, ciphertext) {
  const keyBytes = makeView(aes.encrypt(new Uint8Array(BLOCK_BYTES)));
  const hashKey = new Uint32Array(4);
  for (let i = 0; i < 4; i += 1) hashKey[i] = keyBytes.getUint32(4 * i);
  const accumulator = new Uint32Array(4);
  append(accumulator, hashKey, aad);
  append(accumulator, hashKey, ciphertext);
  const lengths = new Uint8Array(BLOCK_BYTES);
  const footer = makeView(lengths);
  footer.setBigUint64(0, 8n * BigInt(aad.length));
  footer.setBigUint64(8, 8n * BigInt(ciphertext.length));
  append(accumulator, hashKey, lengths);
  const tag = aes.encrypt(counter);
  const words = makeView(tag);
  for (let i = 0; i < 4; i += 1) words.setUint32(4 * i, words.getUint32(4 * i) ^ accumulator[i]);
  return tag;
}

function validateLengths(aad, data) {
  if (data.length > MAX_MESSAGE) throw new RangeError('AES-256-GCM payload exceeds its counter domain');
  if (BigInt(aad.length) > MAX_AAD) throw new RangeError('AES-256-GCM AAD exceeds its length domain');
}

export function seal(key, nonce, aad, plaintext) {
  const aadBytes = asUint8Array(aad);
  const payload = asUint8Array(plaintext);
  validateLengths(aadBytes, payload);
  const aes = new Aes256(key);
  const counter = initialCounter(asUint8Array(nonce));
  const ciphertext = applyPayload(aes, counter.slice(), payload);
  const tag = authenticate(aes, counter, aadBytes, ciphertext);
  return { ciphertext, tag };
}

export function open(key, nonce, aad, ciphertext, tag) {
  const aadBytes = asUint8Array(aad);
  const payload = asUint8Array(ciphertext);
  const received = asUint8Array(tag);
  validateLengths(aadBytes, payload);
  if (received.length !== BLOCK_BYTES) return null;
  const aes = new Aes256(key);
  const counter = initialCounter(asUint8Array(nonce));
  const expected = authenticate(aes, counter, aadBytes, payload);
  let difference = 0;
  for (let i = 0; i < BLOCK_BYTES; i += 1) difference |= expected[i] ^ received[i];
  if (difference !== 0) return null;
  return applyPayload(aes, counter, payload);
}
