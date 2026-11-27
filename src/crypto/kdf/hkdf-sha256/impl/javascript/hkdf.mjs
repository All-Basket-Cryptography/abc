import { MAX_INPUT_BYTES, TAG_BYTES, HmacSha256, authenticate } from '../../../../mac/hmac-sha256/impl/javascript/hmac.mjs';

export const MAX_OUTPUT_BYTES = 255 * TAG_BYTES;

export function extract(salt, inputKeyMaterial) {
  return authenticate(salt === null ? new Uint8Array(TAG_BYTES) : salt, inputKeyMaterial);
}

export function expand(prk, info, outputLength) {
  if (!(prk instanceof Uint8Array) || !(info instanceof Uint8Array)) throw new TypeError('HKDF inputs must be Uint8Array');
  if (prk.length < TAG_BYTES) throw new RangeError('HKDF PRK must have at least 32 bytes');
  if (!Number.isInteger(outputLength) || outputLength < 0 || outputLength > MAX_OUTPUT_BYTES) {
    throw new RangeError('HKDF output length must be an integer from 0 through 8160');
  }
  if (outputLength === 0) return new Uint8Array(0);
  const overhead = outputLength > TAG_BYTES ? BigInt(TAG_BYTES + 1) : 1n;
  if (BigInt(info.length) > MAX_INPUT_BYTES - overhead) throw new RangeError('HKDF info exceeds the HMAC message domain');

  const output = new Uint8Array(outputLength);
  const mac = new HmacSha256(prk);
  let previous = new Uint8Array(0);
  for (let offset = 0, counter = 1; offset < output.length; offset += TAG_BYTES, counter += 1) {
    if (counter !== 1) mac.reset().update(previous);
    previous = mac.update(info).update(Uint8Array.of(counter)).digest();
    output.set(previous.subarray(0, output.length - offset), offset);
  }
  return output;
}

export function derive(salt, inputKeyMaterial, info, outputLength) {
  return expand(extract(salt, inputKeyMaterial), info, outputLength);
}
