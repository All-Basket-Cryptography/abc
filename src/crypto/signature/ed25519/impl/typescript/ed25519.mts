import { asUint8Array } from '../../../../inputs/bytes.mts';
import { nativePublicKey, nativeEd25519Sign, nativeEd25519Verify } from '../../../../providers/ecmascript/node-crypto.mjs';
import { ed25519 } from '../../../../providers/ecmascript/noble.mts';

const KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;
const ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;

function fixed(value: Uint8Array, length: number) {
  const bytes = asUint8Array(value);
  if (bytes.length !== length) throw new RangeError('Invalid Ed25519 key or signature length');
  return bytes;
}

function isStrictPoint(bytes: Uint8Array) {
  try {
    const point = ed25519.Point.fromBytes(bytes, false);
    return !point.isSmallOrder() && point.toBytes().every((value, i) => value === bytes[i]);
  } catch {
    return false;
  }
}

export function publicKey(seed: Uint8Array) {
  return nativePublicKey('ed25519', fixed(seed, KEY_BYTES));
}

export function sign(seed: Uint8Array, message: Uint8Array) {
  return nativeEd25519Sign(fixed(seed, KEY_BYTES), asUint8Array(message));
}

export function verify(key: Uint8Array, message: Uint8Array, signature: Uint8Array) {
  const publicBytes = asUint8Array(key);
  const signatureBytes = asUint8Array(signature);
  const data = asUint8Array(message);
  if (publicBytes.length !== KEY_BYTES || signatureBytes.length !== SIGNATURE_BYTES
      || !isStrictPoint(publicBytes) || !isStrictPoint(signatureBytes.subarray(0, 32))) return false;
  let scalar = 0n;
  for (let i = 63; i >= 32; i -= 1) scalar = (scalar << 8n) | BigInt(signatureBytes[i]);
  return scalar < ORDER && nativeEd25519Verify(publicBytes, data, signatureBytes);
}
