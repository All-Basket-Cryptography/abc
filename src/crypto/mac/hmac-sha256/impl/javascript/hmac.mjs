import { MAX_MESSAGE_BYTES, Sha256, sha256 } from '../../../../hash/sha256/impl/javascript/sha256.mjs';

export const TAG_BYTES = 32;
export const MAX_INPUT_BYTES = MAX_MESSAGE_BYTES - 64n;

export class HmacSha256 {
  #inner = new Sha256();
  #innerPad = new Uint8Array(64);
  #outerPad = new Uint8Array(64);

  constructor(key) {
    if (!(key instanceof Uint8Array)) throw new TypeError('HMAC requires a Uint8Array key');
    const material = key.length > 64 ? sha256(key) : key;
    this.#innerPad.fill(0x36);
    this.#outerPad.fill(0x5c);
    for (let i = 0; i < material.length; i += 1) {
      this.#innerPad[i] ^= material[i];
      this.#outerPad[i] ^= material[i];
    }
    this.#inner.update(this.#innerPad);
  }

  reset() {
    this.#inner.reset();
    this.#inner.update(this.#innerPad);
    return this;
  }

  update(data) {
    this.#inner.update(data);
    return this;
  }

  digest() {
    const outer = new Uint8Array(96);
    outer.set(this.#outerPad);
    outer.set(this.#inner.digest(), 64);
    return sha256(outer);
  }
}

export function authenticate(key, message) {
  return new HmacSha256(key).update(message).digest();
}
