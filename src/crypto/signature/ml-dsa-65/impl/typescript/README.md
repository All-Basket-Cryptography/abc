# Pure deterministic ML-DSA-65 in TypeScript

The per-profile entry point is [`ml_dsa_65.mts`](ml_dsa_65.mts). The adapter calls the pinned Noble source package. Runtime tests run on Node.js.

Use a 32-byte seed, a 1952-byte verification key and a 3309-byte signature. The raw context is optional and admits up to 255 bytes. Signing uses the deterministic FIPS 204 mode.

Use the pinned [provider setup](../../../../providers/ecmascript/README.md), then run this command from the repository root.

```sh
node --test src/crypto/signature/ml-dsa-65/impl/typescript/ml_dsa_65.test.mts
```

The tests check NIST ACVP key generation and signature verdicts and deterministic results across contexts.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
