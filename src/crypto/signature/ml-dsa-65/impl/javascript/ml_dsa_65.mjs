import { asUint8Array } from '../../../../inputs/bytes.mjs';
import { ml_dsa65 } from '../../../../providers/ecmascript/noble.mjs';

export const SEED_BYTES = 32;
export const PUBLIC_KEY_BYTES = 1952;
export const SIGNATURE_BYTES = 3309;
const EMPTY = new Uint8Array(0);

function fixedSeed(value) {
  const bytes = asUint8Array(value);
  if (bytes.length !== SEED_BYTES) throw new RangeError('ML-DSA-65 requires a 32-byte seed');
  return bytes;
}

function validateContext(context) {
  const bytes = asUint8Array(context);
  if (bytes.length > 255) throw new RangeError('ML-DSA-65 context exceeds 255 bytes');
  return bytes;
}

export function publicKey(seed) {
  const pair = ml_dsa65.keygen(fixedSeed(seed));
  pair.secretKey.fill(0);
  return pair.publicKey;
}

export function sign(seed, message, context = EMPTY) {
  const domain = validateContext(context);
  const data = asUint8Array(message);
  const { secretKey } = ml_dsa65.keygen(fixedSeed(seed));
  try {
    return ml_dsa65.sign(data, secretKey, { context: domain, extraEntropy: false });
  } finally {
    secretKey.fill(0);
  }
}

export function verify(key, message, signature, context = EMPTY) {
  const bytes = asUint8Array(key);
  const data = asUint8Array(message);
  const sig = asUint8Array(signature);
  const domain = validateContext(context);
  if (bytes.length !== PUBLIC_KEY_BYTES || sig.length !== SIGNATURE_BYTES) return false;
  return ml_dsa65.verify(sig, data, bytes, { context: domain });
}
