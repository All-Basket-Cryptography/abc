# ECMAScript byte-view qualification

The suite exercises the 20 portfolio profiles from their normal JavaScript
and TypeScript entry points. For each tested byte argument, the suite
compares an ordinary `Uint8Array` with a same-content, nonzero-offset view
whose accessors and methods are shadowed. It also checks that detached and
shared backing buffers are rejected. Additional cases check SHA-256,
SHA-512, and SHA3-256 state after rejected updates, SHAKE256 cursor
preservation, and the exact direct Keccak word-view write range.

Use Node 24.12.0. The pinned test provider supplies a deterministic public
ML-KEM ciphertext fixture. The production API retains randomized
encapsulation.

```sh
npm ci --ignore-scripts --no-audit --prefix src/crypto/providers/ecmascript
node --test tools/compatibility/ecmascript-views/portfolio.test.mjs
```

The byte-view functions use intrinsic typed-array and ArrayBuffer accessors
before reading length or constructing a fixed-length view. The contract
accepts attached `ArrayBuffer` views with nonzero offsets, including
in-bounds resizable buffers. Callers can copy shared bytes into private
storage when they need an immutable call input. Target leakage and
provider arithmetic have independent evidence requirements.
[ECMAScript typed arrays](https://tc39.es/ecma262/multipage/indexed-collections.html#sec-typedarray-objects)
