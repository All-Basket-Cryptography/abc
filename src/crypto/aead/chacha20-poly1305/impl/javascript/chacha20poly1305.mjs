import { applyKeystream, block } from '../../../../cipher/chacha20/impl/javascript/chacha20.mjs';
import { Poly1305 } from '../../../../mac/poly1305/impl/javascript/poly1305.mjs';

const MAX_PAYLOAD = 0xffffffff * 64;
const TAG_BYTES = 16;
const ZEROES = new Uint8Array(16);

function inputLength(bytes) {
  if (!(bytes instanceof Uint8Array) || !(bytes.buffer instanceof ArrayBuffer)) {
    throw new TypeError('AEAD requires Uint8Array backed by an ArrayBuffer');
  }
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).byteLength;
}

function appendPadded(mac, bytes, length) {
  mac.update(bytes);
  const pad = (16 - (length % 16)) % 16;
  if (pad !== 0) mac.update(ZEROES.subarray(0, pad));
}

function makeTag(key, nonce, aad, ciphertext, aadLength, dataLength) {
  const oneTime = block(key, nonce, 0);
  const mac = new Poly1305(oneTime.subarray(0, 32));
  oneTime.fill(0);
  appendPadded(mac, aad, aadLength);
  appendPadded(mac, ciphertext, dataLength);
  const footer = new Uint8Array(16);
  const lengths = new DataView(footer.buffer);
  lengths.setBigUint64(0, BigInt(aadLength), true);
  lengths.setBigUint64(8, BigInt(dataLength), true);
  return mac.update(footer).digest();
}

export function seal(key, nonce, aad, plaintext) {
  const aadLength = inputLength(aad);
  const dataLength = inputLength(plaintext);
  if (dataLength > MAX_PAYLOAD) throw new RangeError('ChaCha20-Poly1305 counter would wrap');
  const ciphertext = Uint8Array.from(plaintext);
  applyKeystream(key, nonce, 1, ciphertext);
  const tag = makeTag(key, nonce, aad, ciphertext, aadLength, dataLength);
  return { ciphertext, tag };
}

export function open(key, nonce, aad, ciphertext, tag) {
  const aadLength = inputLength(aad);
  const dataLength = inputLength(ciphertext);
  const tagLength = inputLength(tag);
  if (dataLength > MAX_PAYLOAD) throw new RangeError('ChaCha20-Poly1305 counter would wrap');
  if (tagLength !== TAG_BYTES) return null;
  const expected = makeTag(key, nonce, aad, ciphertext, aadLength, dataLength);
  let different = 0;
  for (let i = 0; i < TAG_BYTES; i += 1) different |= expected[i] ^ tag[i];
  if (different !== 0) return null;
  const plaintext = Uint8Array.from(ciphertext);
  return applyKeystream(key, nonce, 1, plaintext);
}
