# Poly1305 in TypeScript

`authenticate(key, message)` returns a 16-byte tag. `new Poly1305(key).update(bytes).digest()` supports incremental input and snapshot tags. Use each 32-byte key for one message. The ten 13-bit limbs use Number multiplication and fixed carry schedules. The tests cross-check an independent BigInt implementation and the RFC example.

```sh
node --test src/crypto/mac/poly1305/impl/typescript/poly1305.test.mts
```

Inputs are `Uint8Array` views backed by `ArrayBuffer`. The 13-bit
radix model proves the congruence, integer bounds and normalization of
the three carry sweeps. Each convolution column reads ten adjacent
positions from the cached key coefficients in reverse order. Lean
checks every address against the folded convolution and every partial
sum against the exact range for IEEE 754 binary64 integers. Full blocks
are read directly from the caller view using an offset.
Source refinement and runtime leakage qualification remain open.
[Lean coefficient model](../../spec/Poly1305Window.lean) · [Lean carry model](../../spec/Poly1305Radix13.lean)

- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
