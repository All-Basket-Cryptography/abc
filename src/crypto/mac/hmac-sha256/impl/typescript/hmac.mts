import { asUint8Array } from '../../../../inputs/bytes.mts';
import { MAX_MESSAGE_BYTES, Sha256, sha256 } from '../../../../hash/sha256/impl/typescript/sha256.mts';

const blockBytes = 64;
const innerPad = 0x36;
const outerPad = 0x5c;
export const TAG_BYTES = 32;
export const MAX_INPUT_BYTES = MAX_MESSAGE_BYTES - BigInt(blockBytes);

function innerKeyPad(key: Uint8Array): Uint8Array {
  key = asUint8Array(key);
  const material = key.length > blockBytes ? sha256(key) : key;
  const pad = new Uint8Array(blockBytes).fill(innerPad);
  for (let i = 0; i < material.length; ++i) pad[i] ^= material[i];
  if (material !== key) material.fill(0);
  return pad;
}

function convertToOuterPad(pad: Uint8Array): void {
  for (let i = 0; i < pad.length; ++i) pad[i] ^= innerPad ^ outerPad;
}

function finish(outer: Sha256, inner: Sha256): Uint8Array {
  const tag = inner.digest();
  outer.update(tag);
  tag.fill(0);
  const result = outer.digest();
  outer.reset();
  return result;
}

export class HmacSha256 {
  readonly #inner = new Sha256();
  readonly #innerStart = new Sha256();
  readonly #outerStart = new Sha256();
  #outer?: Sha256;

  constructor(key: Uint8Array) {
    const pad = innerKeyPad(key);
    this.#innerStart.update(pad);
    convertToOuterPad(pad);
    this.#outerStart.update(pad);
    pad.fill(0);
    this.#inner.copyFrom(this.#innerStart);
  }

  reset(): this {
    this.#inner.copyFrom(this.#innerStart);
    return this;
  }

  update(bytes: Uint8Array): this {
    this.#inner.update(bytes);
    return this;
  }

  digest(): Uint8Array {
    const outer = this.#outer ??= new Sha256();
    return finish(outer.copyFrom(this.#outerStart), this.#inner);
  }
}

export function authenticate(key: Uint8Array, message: Uint8Array): Uint8Array {
  const pad = innerKeyPad(key);
  const inner = new Sha256().update(pad);
  convertToOuterPad(pad);
  const outer = new Sha256().update(pad);
  pad.fill(0);
  return finish(outer, inner.update(message));
}
