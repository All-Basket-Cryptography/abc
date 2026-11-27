import { MAX_INPUT_BYTES, TAG_BYTES, HmacSha256 } from '../../../../mac/hmac-sha256/impl/typescript/hmac.mts';

const largestIndex = 2 ** 32 - 1;
export const MAX_ITERATIONS = largestIndex;
export const MAX_OUTPUT_BYTES = largestIndex * TAG_BYTES;

function block(mac: HmacSha256, salt: Uint8Array, index: number, iterations: number): Uint8Array {
  const indexBytes = Uint8Array.of(index >>> 24, index >>> 16, index >>> 8, index);
  mac.reset().update(salt).update(indexBytes);
  let term = mac.digest();
  const accumulated = term.slice();
  for (let step = 1; step < iterations; ++step) {
    mac.reset().update(term);
    term = mac.digest();
    for (let i = 0; i < accumulated.length; ++i) accumulated[i] ^= term[i];
  }
  return accumulated;
}

export function derive(password: Uint8Array, salt: Uint8Array, iterations: number, length: number): Uint8Array {
  if (!(password instanceof Uint8Array) || !(salt instanceof Uint8Array)) throw new TypeError('PBKDF2 inputs must be Uint8Array');
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS) {
    throw new RangeError('PBKDF2 iterations must be a positive 32-bit integer');
  }
  if (!Number.isInteger(length) || length < 1 || length > MAX_OUTPUT_BYTES) {
    throw new RangeError('PBKDF2 output length exceeds its positive block-index domain');
  }
  if (BigInt(salt.byteLength) + 4n > MAX_INPUT_BYTES) throw new RangeError('PBKDF2 salt exceeds the HMAC message domain');

  const result = new Uint8Array(length);
  const mac = new HmacSha256(password);
  const blocks = Math.ceil(length / TAG_BYTES);
  for (let blockIndex = 0; blockIndex < blocks; ++blockIndex) {
    const offset = blockIndex * TAG_BYTES;
    const value = block(mac, salt, blockIndex + 1, iterations);
    result.set(value.subarray(0, length - offset), offset);
  }
  return result;
}
