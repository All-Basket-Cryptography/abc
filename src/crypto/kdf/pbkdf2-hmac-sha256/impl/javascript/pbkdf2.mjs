import { asUint8Array } from '../../../../inputs/bytes.mjs';
import { MAX_INPUT_BYTES, TAG_BYTES, HmacSha256 } from '../../../../mac/hmac-sha256/impl/javascript/hmac.mjs';

export const MAX_ITERATIONS = 0xffffffff;
export const MAX_OUTPUT_BYTES = 0xffffffff * TAG_BYTES;

export function derive(password, salt, iterations, outputLength) {
  password = asUint8Array(password);
  salt = asUint8Array(salt);
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS) {
    throw new RangeError('PBKDF2 iterations must be a positive 32-bit integer');
  }
  if (!Number.isInteger(outputLength) || outputLength < 1 || outputLength > MAX_OUTPUT_BYTES) {
    throw new RangeError('PBKDF2 output length exceeds its positive block-index domain');
  }
  if (BigInt(salt.length) > MAX_INPUT_BYTES - 4n) throw new RangeError('PBKDF2 salt exceeds the HMAC message domain');

  const result = new Uint8Array(outputLength);
  const mac = new HmacSha256(password);
  const indexBytes = new Uint8Array(4);
  const indexView = new DataView(indexBytes.buffer);
  for (let offset = 0, index = 1; offset < result.length; offset += TAG_BYTES, index += 1) {
    indexView.setUint32(0, index, false);
    const accumulated = mac.reset().update(salt).update(indexBytes).digest();
    let previous = accumulated;
    for (let i = 1; i < iterations; i += 1) {
      previous = mac.reset().update(previous).digest();
      for (let byte = 0; byte < TAG_BYTES; byte += 1) accumulated[byte] ^= previous[byte];
    }
    result.set(accumulated.subarray(0, result.length - offset), offset);
  }
  return result;
}
