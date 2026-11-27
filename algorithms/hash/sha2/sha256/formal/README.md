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

The abstract stream laws `Stream.update_within_domain`, `Stream.rejects_out_of_domain`, and `Stream.finalize_after_update` were checked with Lean 4.31.0. The executable specification checks also passed. [Recorded toolchain and results](../../../../../docs/status/formal-and-fuzz.md)

## Refinement statements to check

- For every byte sequence in the valid domain, Rust `digest` succeeds and produces exactly `Abc.Spec.Sha256.digest message`.
- For every trace of `update` operations with valid slices, successful updates preserve a state relation to the concatenation of accepted bytes. An update whose mathematical cumulative length exceeds the limit returns `MessageTooLong` with the prior state preserved.
- For every reachable state, consuming `finalize` yields the specification digest for the accepted bytes. Includes the empty trace and every placement of block or padding boundaries.

These are intended claims. The extracted model, state relation, and refinement proofs require a working pinned extractor and checker. Functional refinement addresses API results and state. Cryptographic security, timing, compiler behavior, and target binary correspondence require separate evidence.

## Executable checks

From the repository root on a host with the pinned Lean toolchain, build the shared byte-encoding module, compile the specification, and run its independent vector and boundary checks.

```sh
python foundation/lean/check.py sha256
```

The `abc` vector comes from the NIST SHA-256 example. The empty-message expectation also appears in the NIST CAVP byte-oriented short-message vector set. [NIST intermediate-value example](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha256.pdf) [NIST secure hashing validation examples](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)
