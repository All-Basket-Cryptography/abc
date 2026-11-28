import { applyKeystream, block } from '../../../../cipher/chacha20/impl/javascript/chacha20.mjs';
import { asUint8Array } from '../../../../inputs/bytes.mjs';
import { Poly1305 } from '../../../../mac/poly1305/impl/javascript/poly1305.mjs';

const MAX_PAYLOAD = 0xffffffff * 64;
const TAG_BYTES = 16;
const ZEROES = new Uint8Array(16);

function appendPadded(mac, bytes) {
  mac.update(bytes);
  const pad = (16 - (bytes.length % 16)) % 16;
  if (pad !== 0) mac.update(ZEROES.subarray(0, pad));
}

function makeTag(key, nonce, aad, ciphertext) {
  const oneTime = block(key, nonce, 0);
  const mac = new Poly1305(oneTime.subarray(0, 32));
  oneTime.fill(0);
  appendPadded(mac, aad);
  appendPadded(mac, ciphertext);
  const footer = new Uint8Array(16);
  const lengths = new DataView(footer.buffer);
  lengths.setBigUint64(0, BigInt(aad.length), true);
  lengths.setBigUint64(8, BigInt(ciphertext.length), true);
  return mac.update(footer).digest();
}

export function seal(key, nonce, aad, plaintext) {
  const keyBytes = asUint8Array(key);
  const nonceBytes = asUint8Array(nonce);
  const aadBytes = asUint8Array(aad);
  const plaintextBytes = asUint8Array(plaintext);
  if (plaintextBytes.length > MAX_PAYLOAD) throw new RangeError('ChaCha20-Poly1305 counter would wrap');
  const ciphertext = new Uint8Array(plaintextBytes);
  applyKeystream(keyBytes, nonceBytes, 1, ciphertext);
  const tag = makeTag(keyBytes, nonceBytes, aadBytes, ciphertext);
  return { ciphertext, tag };
}

export function open(key, nonce, aad, ciphertext, tag) {
  const aadBytes = asUint8Array(aad);
  const ciphertextBytes = asUint8Array(ciphertext);
  const tagBytes = asUint8Array(tag);
  if (ciphertextBytes.length > MAX_PAYLOAD) throw new RangeError('ChaCha20-Poly1305 counter would wrap');
  if (tagBytes.length !== TAG_BYTES) return null;
  const keyBytes = asUint8Array(key);
  const nonceBytes = asUint8Array(nonce);
  const expected = makeTag(keyBytes, nonceBytes, aadBytes, ciphertextBytes);
  let different = 0;
  for (let i = 0; i < TAG_BYTES; i += 1) different |= expected[i] ^ tagBytes[i];
  if (different !== 0) return null;
  // The authenticated view has unshared storage, and copying it calls no caller code.
  const plaintext = new Uint8Array(ciphertextBytes);
  return applyKeystream(keyBytes, nonceBytes, 1, plaintext);
}
