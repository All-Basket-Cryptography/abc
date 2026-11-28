# ML-KEM-768 in JavaScript

The per-profile entry point is [`ml_kem_768.mjs`](ml_kem_768.mjs). The adapter calls the pinned Noble source package. Runtime tests run on Node.js.

Use a 64-byte d∥z seed, a 1184-byte encapsulation key and a 1088-byte ciphertext. Encapsulation uses fresh provider randomness. A correctly sized altered ciphertext produces a 32-byte implicit-rejection secret.

Use the pinned [provider setup](../../../../providers/ecmascript/README.md), then run this command from the repository root.

```sh
node --test src/crypto/agreement/ml-kem-768/impl/javascript/ml_kem_768.test.mjs
```

The tests compare NIST ACVP public keys, both sides of encapsulation across providers, key canonicality and implicit rejection.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
