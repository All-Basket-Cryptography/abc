# SHA-512 functional model verification

Lean checks that the fixed-array model of portable Rust SHA-512 compression
matches the FIPS model for any 128 input bytes and any eight 64-bit chaining
words. The proof covers the sixteen big-endian input words, all 64 schedule
extensions, all 80 rounds and all eight feed-forward additions. The
compression theorem is lifted to the portable model of the byte API. The
one-shot result agrees with the FIPS model on every byte list, including
length rejection. For arbitrary finite update traces, the streaming result
equals the digest of accepted chunks in order. If the total length is
admissible, it equals the digest of the concatenation for every partition.
The model checks the 128-bit bit length and both final padding branches.
[FIPS 180-4, §§ 4.1.3, 4.2.3, 5.1.2, 5.2.2 and 6.4.2](https://doi.org/10.6028/NIST.FIPS.180-4)

The checker pins the reviewed production source and the compression body. It
extracts the literal initialization and round tables into a fresh Lean
module. An integer calculation independently verifies the round words from
the first eighty prime cube roots and the initialization words from the
first eight prime square roots. Lean compares the generated tables with the
standard's tables. The block, one-shot and stream statements are checked
separately from the model. The receipt records the axiom dependencies of
fifteen theorems.

Run from the repository root with Lean 4.31.0 available through elan or on
`PATH`. Use `--lean` to select a standalone executable.

```sh
python -B tools/verification/sha512/check.py --negative-controls
```

The negative checks reject five changes in temporary inputs. They alter a
Rust rotation, round constant and padding marker, and repeat the rotation
and padding mutations in the Lean model. The Lean changes must break
equality with the FIPS round and padding specifications.

The original Rust source is linked to the functional model through source
review and fingerprint checks. Compiler-level translation and raw array
state outside the live prefix remain source-refinement obligations.
Constant-time behaviour, compiler output and the other language
implementations have separate verification scope.
[Compression theorem](../../../src/crypto/hash/sha512/spec/Sha512Compression.lean) · [Stream theorems](../../../src/crypto/hash/sha512/spec/Sha512Streaming.lean) · [FIPS model](../../../src/crypto/hash/sha512/spec/Sha512Spec.lean) · [Windows x64 receipt](receipt-windows-x64.json)
