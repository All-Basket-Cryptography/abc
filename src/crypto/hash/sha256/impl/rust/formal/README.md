# SHA-256 specification

`Sha256Spec.lean` models the byte-aligned API from the August 2015 edition of FIPS 180-4. The published PDF incorporates the 2014 editorial erratum to § 4.1.1 for SHA-1. The SHA-256 specification uses § 4.1.2. [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

| Spec definition | Standard section | Scope |
|---|---|---|
| `byteLengthAllowed`, `padding` | §§ 3.1, 5.1.1, 6.2 | A whole-byte message with `8 * length < 2^64`. The length suffix is an unsigned 64-bit big-endian value. |
| `parseWord`, `messageSchedule` | §§ 5.2.1, 6.2.2(1) | Sixteen words parsed in big-endian order and expanded to 64 words. |
| `initial`, `round`, `compress` | §§ 4.1.2, 4.2.2, 5.3.3, 6.2.2 | IV, functions, constants, and modulo-2^32 working state. |
| `digest`, `encode` | § 6.2.2 | Final concatenation in big-endian word order. |
| `Stream.init`, `Stream.update`, `Stream.finalize` | ABC byte API contract | Accept updates additively in order. Reject overflow before changing the prior state. Finalization observes the concatenated message. |

The model uses mathematical lists and bitvectors. It has no dependency on the Rust crate, extracted Rust models, or runtime buffer representation. Its memory use follows the abstract message trace. Arbitrary bit-length messages outside the byte-aligned API remain outside these definitions.

Lean 4.31.0 checks the specification, fixed-array compression arithmetic and schedule, and an independent streaming buffer model. Its trace theorems cover arbitrary chunk partitions and finalization after successful and rejected updates. The executable specification checks also passed. [Recorded toolchain and results](../../../../../../../docs/status/formal-and-fuzz.md)

## Checked Rust refinement

- `digest_refines` checks that the extracted one-shot digest succeeds with the specification's bytes on every allowed input and reports `MessageTooLong` outside the allowed length.
- `new_refines` establishes the initial state relation. `update_refines` preserves it and returns the exact prior Rust state with `MessageTooLong` when the cumulative length exceeds the limit.
- `finalize_trace_refines` checks the digest of all accepted bytes for every finite call trace. `finalize_trace_refines_concat` identifies that message with the concatenated input when its length is allowed.

The checked declarations are in namespace `Abc.Refine.Sha256.Implementation`. Functional refinement covers results, state, termination, and the absence of panics in the extracted model for the specified inputs. Cryptographic security, timing, compiler behavior, and target binary correspondence require separate evidence.

## Executable checks

From the repository root on a host with the pinned Lean toolchain, build the shared byte-encoding module, compile the specification, and run its independent vector and boundary checks.

```sh
python src/lean/check.py sha256
```

On Linux x86-64, point `ABC_AENEAS_ROOT` at the pinned Aeneas checkout with the verified Aeneas binary in `bin/` and the pinned Charon checkout and binary in `charon/` and `charon/bin/`. With the pinned Rust and Lean toolchains available, regenerate the model twice and then use the emitted result path to check it.

```sh
node src/crypto/hash/sha256/impl/rust/formal/extract.mjs
node src/crypto/hash/sha256/impl/rust/formal/check-model.mjs .abc/sha256-extraction/run-EXAMPLE/result.json
```

The [advisory extraction workflow](../../../../../../../.github/workflows/sha256-model.yml) verifies the downloaded tool binaries. The checker binds the proof to the exact Rust source, extraction target without Cargo features, and both unmodified generated Lean modules. It checks the exported claims against `TrustedClaims.lean` and audits their transitive axiom dependencies. The workflow publishes the extraction and proof reports, including source and model digests. Local generated files live beneath `.abc/`.

The `abc` vector comes from the NIST SHA-256 example. The empty-message expectation also appears in the NIST CAVP byte-oriented short-message vector set. [NIST intermediate-value example](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha256.pdf) [NIST secure hashing validation examples](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)
