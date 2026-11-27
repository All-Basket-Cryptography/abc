# Poly1305 in TypeScript

`authenticate(key, message)` returns a 16-byte tag. `new Poly1305(key).update(bytes).digest()` supports incremental input and snapshot tags. Use each 32-byte key for one message. The ten 13-bit limbs use Number multiplication and fixed carry schedules. The tests cross-check an independent BigInt implementation and the RFC example.

```sh
node --test src/crypto/mac/poly1305/impl/typescript/poly1305.test.mts
```

Inputs are `Uint8Array` views backed by `ArrayBuffer`. The 13-bit
radix model proves the congruence, integer bounds, and normalization of
the three carry sweeps. Original-source and runtime leakage refinements
remain open. [Lean carry model](../../spec/Poly1305Radix13.lean)

- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
