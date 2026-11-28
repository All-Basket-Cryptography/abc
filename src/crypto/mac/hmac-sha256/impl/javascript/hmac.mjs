import { asUint8Array } from '../../../../inputs/bytes.mjs';
import { MAX_MESSAGE_BYTES, Sha256, sha256 } from '../../../../hash/sha256/impl/javascript/sha256.mjs';

const BLOCK_BYTES = 64;
const INNER_PAD = 0x36;
const OUTER_PAD = 0x5c;
export const TAG_BYTES = 32;
export const MAX_INPUT_BYTES = MAX_MESSAGE_BYTES - BigInt(BLOCK_BYTES);

function innerKeyPad(key) {
  key = asUint8Array(key);
  const material = key.length > BLOCK_BYTES ? sha256(key) : key;
  const pad = new Uint8Array(BLOCK_BYTES).fill(INNER_PAD);
  for (let i = 0; i < material.length; i += 1) pad[i] ^= material[i];
  if (material !== key) material.fill(0);
  return pad;
}

function convertToOuterPad(pad) {
  for (let i = 0; i < pad.length; i += 1) pad[i] ^= INNER_PAD ^ OUTER_PAD;
}

function finish(outer, inner) {
  const tag = inner.digest();
  outer.update(tag);
  tag.fill(0);
  const result = outer.digest();
  outer.reset();
  return result;
}

export class HmacSha256 {
  #inner = new Sha256();
  #innerStart = new Sha256();
  #outerStart = new Sha256();
  #outer;

  constructor(key) {
    const pad = innerKeyPad(key);
    this.#innerStart.update(pad);
    convertToOuterPad(pad);
    this.#outerStart.update(pad);
    pad.fill(0);
    this.#inner.copyFrom(this.#innerStart);
  }

  reset() {
    this.#inner.copyFrom(this.#innerStart);
    return this;
  }

  update(data) {
    this.#inner.update(data);
    return this;
  }

  digest() {
    const outer = this.#outer ??= new Sha256();
    return finish(outer.copyFrom(this.#outerStart), this.#inner);
  }
}

export function authenticate(key, message) {
  const pad = innerKeyPad(key);
  const inner = new Sha256().update(pad);
  convertToOuterPad(pad);
  const outer = new Sha256().update(pad);
  pad.fill(0);
  return finish(outer, inner.update(message));
}
