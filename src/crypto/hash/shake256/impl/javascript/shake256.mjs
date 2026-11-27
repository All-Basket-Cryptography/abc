import { Sponge } from '../../../keccak-p1600/impl/javascript/keccak.mjs';

export class Shake256 {
  #sponge = new Sponge();

  update(input) {
    this.#sponge.update(input);
    return this;
  }

  finalize() {
    return this.#sponge.reader(0x1f);
  }
}

export function shake256(input, size) {
  return new Shake256().update(input).finalize().read(size);
}
