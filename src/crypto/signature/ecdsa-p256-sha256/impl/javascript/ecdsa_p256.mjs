import { asUint8Array } from '../../../../inputs/bytes.mjs';
import { p256 } from '../../../../providers/ecmascript/noble.mjs';

function fixedPrivate(key) {
  const bytes = asUint8Array(key);
  if (bytes.length !== 32 || !p256.utils.isValidSecretKey(bytes)) {
    throw new RangeError('Invalid P-256 private scalar');
  }
  return bytes;
}

export function publicKey(key) {
  return p256.getPublicKey(fixedPrivate(key), false);
}

export function sign(key, message) {
  return p256.sign(asUint8Array(message), fixedPrivate(key),
    { prehash: true, lowS: false, extraEntropy: false, format: 'compact' });
}

export function verify(key, message, signature) {
  const bytes = asUint8Array(key);
  const data = asUint8Array(message);
  const sig = asUint8Array(signature);
  const sec1 = (bytes.length === 33 && (bytes[0] === 2 || bytes[0] === 3))
    || (bytes.length === 65 && bytes[0] === 4);
  if (!sec1 || sig.length !== 64) return false;
  return p256.verify(sig, data, bytes, { prehash: true, lowS: false, format: 'compact' });
}
