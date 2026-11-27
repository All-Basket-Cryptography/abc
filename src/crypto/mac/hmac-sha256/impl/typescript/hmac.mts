import { MAX_MESSAGE_BYTES, Sha256, sha256 } from '../../../../hash/sha256/impl/typescript/sha256.mts';

const blockBytes = 64;
export const TAG_BYTES = 32;
export const MAX_INPUT_BYTES = MAX_MESSAGE_BYTES - BigInt(blockBytes);

export class HmacSha256 {
  readonly #inner = new Sha256();
  readonly #keyBlock: Uint8Array;
  readonly #outerPad: Uint8Array;

  constructor(key: Uint8Array) {
    if (!(key instanceof Uint8Array)) throw new TypeError('HMAC requires a Uint8Array key');
    this.#keyBlock = new Uint8Array(blockBytes);
    this.#keyBlock.set(key.length > blockBytes ? sha256(key) : key);
    this.#outerPad = this.#keyBlock.map((byte) => byte ^ 0x5c);
    // Store the inner pad in the original block after deriving the outer pad.
    for (let i = 0; i < blockBytes; ++i) this.#keyBlock[i] ^= 0x36;
    this.#inner.update(this.#keyBlock);
  }

  reset(): this {
    this.#inner.reset();
    this.#inner.update(this.#keyBlock);
    return this;
  }

  update(bytes: Uint8Array): this {
    this.#inner.update(bytes);
    return this;
  }

  digest(): Uint8Array {
    return new Sha256().update(this.#outerPad).update(this.#inner.digest()).digest();
  }
}

export function authenticate(key: Uint8Array, message: Uint8Array): Uint8Array {
  const mac = new HmacSha256(key);
  mac.update(message);
  return mac.digest();
}
