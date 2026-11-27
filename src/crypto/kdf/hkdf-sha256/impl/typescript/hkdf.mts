import { MAX_INPUT_BYTES, TAG_BYTES, HmacSha256, authenticate } from '../../../../mac/hmac-sha256/impl/typescript/hmac.mts';

export const MAX_OUTPUT_BYTES = 255 * TAG_BYTES;

export function extract(salt: Uint8Array | null, inputKeyMaterial: Uint8Array): Uint8Array {
  return authenticate(salt === null ? new Uint8Array(TAG_BYTES) : salt, inputKeyMaterial);
}

export function expand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (!(prk instanceof Uint8Array) || !(info instanceof Uint8Array)) throw new TypeError('HKDF inputs must be Uint8Array');
  if (prk.length < TAG_BYTES) throw new RangeError('HKDF PRK must have at least 32 bytes');
  if (!Number.isInteger(length) || length < 0 || length > MAX_OUTPUT_BYTES) {
    throw new RangeError('HKDF output length must be an integer from 0 through 8160');
  }
  if (length === 0) return new Uint8Array(0);
  const contextLength = BigInt(info.byteLength) + BigInt(length > TAG_BYTES ? TAG_BYTES + 1 : 1);
  if (contextLength > MAX_INPUT_BYTES) throw new RangeError('HKDF info exceeds the HMAC message domain');

  const output = new Uint8Array(length);
  const counter = new Uint8Array(1);
  const mac = new HmacSha256(prk);
  let lastTag: Uint8Array | undefined;
  for (let i = 0; i < Math.ceil(length / TAG_BYTES); ++i) {
    if (lastTag !== undefined) mac.reset().update(lastTag);
    counter[0] = i + 1;
    mac.update(info);
    mac.update(counter);
    lastTag = mac.digest();
    const start = i * TAG_BYTES;
    output.set(lastTag.subarray(0, length - start), start);
  }
  return output;
}

export function derive(salt: Uint8Array | null, inputKeyMaterial: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const prk = extract(salt, inputKeyMaterial);
  return expand(prk, info, length);
}
