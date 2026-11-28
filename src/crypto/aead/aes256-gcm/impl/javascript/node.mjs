import { createCipheriv, createDecipheriv } from 'node:crypto';
import { asUint8Array } from '../../../../inputs/bytes.mjs';

const TAG_BYTES = 16;
const MAX_PAYLOAD = (2 ** 32 - 2) * 16;
const AAD_LIMIT = 2 ** 61;

function validateLengths(aad, payload) {
  if (payload.length > MAX_PAYLOAD) throw new RangeError('AES-256-GCM payload exceeds its counter domain');
  if (aad.length >= AAD_LIMIT) throw new RangeError('AES-256-GCM AAD exceeds its length domain');
}

function keyAndNonce(key, nonce) {
  const keyBytes = asUint8Array(key);
  if (keyBytes.length !== 32) throw new RangeError('AES-256 requires a 32-byte key');
  const nonceBytes = asUint8Array(nonce);
  if (nonceBytes.length !== 12) throw new RangeError('AES-256-GCM requires a 12-byte nonce');
  return [keyBytes, nonceBytes];
}

function joinChunks(first, last) {
  const bytes = new Uint8Array(first.length + last.length);
  bytes.set(first);
  bytes.set(last, first.length);
  return bytes;
}

function isAuthenticationFailure(error) {
  // Node 24.12.0 emits this unadorned Error for GCM tag mismatch.
  return error instanceof Error && error.message === 'Unsupported state or unable to authenticate data' &&
    !('code' in error) && !('opensslErrorStack' in error);
}

export function seal(key, nonce, aad, plaintext) {
  const header = asUint8Array(aad);
  const payload = asUint8Array(plaintext);
  validateLengths(header, payload);
  const [keyBytes, nonceBytes] = keyAndNonce(key, nonce);
  const cipher = createCipheriv('aes-256-gcm', keyBytes, nonceBytes, { authTagLength: TAG_BYTES });
  cipher.setAAD(header);
  const ciphertext = joinChunks(cipher.update(payload), cipher.final());
  return { ciphertext, tag: new Uint8Array(cipher.getAuthTag()) };
}

export function open(key, nonce, aad, ciphertext, tag) {
  const header = asUint8Array(aad);
  const payload = asUint8Array(ciphertext);
  const received = asUint8Array(tag);
  validateLengths(header, payload);
  if (received.length !== TAG_BYTES) return null;
  const [keyBytes, nonceBytes] = keyAndNonce(key, nonce);
  const decipher = createDecipheriv('aes-256-gcm', keyBytes, nonceBytes, { authTagLength: TAG_BYTES });
  decipher.setAAD(header);
  decipher.setAuthTag(received);
  const first = decipher.update(payload);
  let last;
  try {
    try {
      last = decipher.final();
    } catch (error) {
      if (isAuthenticationFailure(error)) return null;
      throw error;
    }
    return joinChunks(first, last);
  } finally {
    first.fill(0);
    last?.fill(0);
  }
}
