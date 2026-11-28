# Provider input encoding models

These Lean models describe the byte-level input contracts shared by
SDKs that import ML-KEM-768 encapsulation keys or X25519 peer
coordinates. Theorems quantify over the complete fixed-width input
domains. The models provide conformance targets for source-level
refinement of each adapter.

## ML-KEM-768

A byte triple consists of three unsigned octets. A coefficient pair
consists of two 12-bit values. Lean proves that unpacking matches the
mask, shift and OR expressions, preserves the little-endian value of
the complete triple, and is inverse to packing in both directions.

A triple is accepted exactly when reduction modulo 3,329 and
re-encoding reproduce its original bytes. Across an encapsulation key,
the same equivalence checks all 384 triples. Their 768 coefficients
occupy the initial 1,152 bytes. The remaining 32 bytes of `rho` are
preserved by the model.
[FIPS 203, Algorithms 5 and 6 and §7.2](https://doi.org/10.6028/NIST.FIPS.203)

## X25519

Clearing the highest bit of the last byte in the little-endian wire
encoding is equivalent to taking the remainder modulo `2^255`.
Lean proves that reduction modulo `2^255 - 19` then needs at most
one subtraction, preserves canonical coordinates and is idempotent.
For all 256-bit input words, the alias theorem gives exactly two
representations for canonical coordinates at least 19 and exactly four
for coordinates below 19. The two additional forms encode a masked
value at or above the field modulus.
[RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748.html#section-5)

## Verification scope

```sh
lean --version
lean -DwarningAsError=true src/crypto/providers/formal/MlKem768InputEncoding.lean
lean -DwarningAsError=true src/crypto/providers/formal/X25519InputEncoding.lean
```

Lean 4.31.0 checks both modules. The printed transitive axiom
dependencies are drawn from `propext`, `Classical.choice` and
`Quot.sound`. The proof scope ends at input encoding and modular
normalization. Adapter source correspondence, provider arithmetic,
key agreement behavior and compiled leakage evidence remain separate
verification work.
