import { Sponge } from '../../../keccak-p1600/impl/typescript/keccak.mts';

export class Shake256 {
  #sponge = new Sponge();

  update(input: Uint8Array) {
    this.#sponge.update(input);
    return this;
  }

  finalize() {
    return this.#sponge.reader(0x1f);
  }
}

export function shake256(input: Uint8Array, size: number) {
  return new Shake256().update(input).finalize().read(size);
}
