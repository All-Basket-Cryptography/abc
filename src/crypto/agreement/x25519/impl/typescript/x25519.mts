import { asUint8Array } from '../../../../inputs/bytes.mts';
import { nativePublicKey, nativeX25519 } from '../../../../providers/ecmascript/node-crypto.mjs';

const WIDTH = 32;

function fixed(value: Uint8Array) {
  const bytes = asUint8Array(value);
  if (bytes.length !== WIDTH) throw new RangeError('X25519 requires a 32-byte input');
  return bytes;
}

function canonicalPeer(peer: Uint8Array) {
  const bytes = new Uint8Array(fixed(peer));
  bytes[31] &= 127;
  // After masking, any noncanonical u lies in [2^255 - 19, 2^255 - 1].
  if (bytes[31] === 127 && bytes.slice(1, 31).every(byte => byte === 255) && bytes[0] >= 237) {
    const reduced = bytes[0] - 237;
    bytes.fill(0);
    bytes[0] = reduced;
  }
  return bytes;
}

export function publicKey(secret: Uint8Array) {
  return nativePublicKey('x25519', fixed(secret));
}

export function sharedSecret(secret: Uint8Array, peer: Uint8Array) {
  return nativeX25519(fixed(secret), canonicalPeer(peer));
}
