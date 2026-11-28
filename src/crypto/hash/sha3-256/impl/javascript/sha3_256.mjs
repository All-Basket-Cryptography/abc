import { Sponge } from '../../../keccak-p1600/impl/javascript/keccak.mjs';

export class Sha3_256 {
  #sponge = new Sponge();

  update(input) {
    this.#sponge.update(input);
    return this;
  }

  digest() {
    return this.#sponge.reader(0x06).read(32);
  }
}

export function sha3_256(input) {
  return new Sha3_256().update(input).digest();
}
