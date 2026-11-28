import { asUint8Array } from '../../../../inputs/bytes.mts';
import { ml_kem768 } from '../../../../providers/ecmascript/noble.mts';

export const SEED_BYTES = 64;
export const PUBLIC_KEY_BYTES = 1184;
export const CIPHERTEXT_BYTES = 1088;

function fixed(value: Uint8Array, length: number) {
  const bytes = asUint8Array(value);
  if (bytes.length !== length) throw new RangeError('Invalid ML-KEM-768 encoding length');
  return bytes;
}

export function publicKey(seed: Uint8Array) {
  const pair = ml_kem768.keygen(fixed(seed, SEED_BYTES));
  pair.secretKey.fill(0);
  return pair.publicKey;
}

export function encapsulate(key: Uint8Array) {
  const { cipherText: ciphertext, sharedSecret } = ml_kem768.encapsulate(fixed(key, PUBLIC_KEY_BYTES));
  return { ciphertext, sharedSecret };
}

export function decapsulate(seed: Uint8Array, ciphertext: Uint8Array) {
  const wire = fixed(ciphertext, CIPHERTEXT_BYTES);
  const { secretKey } = ml_kem768.keygen(fixed(seed, SEED_BYTES));
  try {
    return ml_kem768.decapsulate(wire, secretKey);
  } finally {
    secretKey.fill(0);
  }
}
