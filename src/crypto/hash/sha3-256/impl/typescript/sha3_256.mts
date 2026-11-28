import { Sponge } from '../../../keccak-p1600/impl/typescript/keccak.mts';

export class Sha3_256 {
  #sponge = new Sponge();

  update(input: Uint8Array) {
    this.#sponge.update(input);
    return this;
  }

  digest() {
    return this.#sponge.reader(0x06).read(32);
  }
}

export function sha3_256(input: Uint8Array) {
  return new Sha3_256().update(input).digest();
}
