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

The standalone functional replay links the reviewed Rust source to the
model with fingerprint checks. The source replay below adds generated
terms from the compression function's compiler intermediate representation.
[Compression theorem](../../../src/crypto/hash/sha512/spec/Sha512Compression.lean) · [Stream theorems](../../../src/crypto/hash/sha512/spec/Sha512Streaming.lean) · [FIPS model](../../../src/crypto/hash/sha512/spec/Sha512Spec.lean) · [Windows x64 receipt](receipt-windows-x64.json)

## Charon compression source replay

The source replay invokes pinned Charon `b104e24` with Rust
`nightly-2026-08-18` on the original crate's `compress` function. It
lowers four normal-path bodies from Charon's structured LLBC into Lean.
The generated expressions cover loading a big-endian word, reading and
writing the schedule indices, all eight round outputs and the
feed-forward addition. Lean composes these four expressions with the
existing fixed-array driver model and proves equality to the separate
FIPS compression specification for every 128-byte block and eight
64-bit initial words. The receipt audits six theorems.
[Charon](https://github.com/AeneasVerif/charon) · [Rust unsigned-word primitives](https://doc.rust-lang.org/std/primitive.u64.html) · [Generated-term refinement](../../../src/crypto/hash/sha512/spec/Sha512LlbcRefinement.lean)

With the LLVM linker, pinned Charon and Rust toolchain on the host and
Lean 4.31.0 installed, run the source replay from the repository root.
`--charon` and `--lean` accept explicit executable paths.

```sh
python -B tools/verification/sha512/check_source.py --negative-controls
```

The checker requires that two fresh crate extractions generate identical
Lean terms. The negative control recompiles a Rust copy with a changed
rotation, lowers its changed LLBC and confirms that Lean rejects the
round equality. The Windows x64 run used Charon's distributed Rust sysroot
fallback and records both LLBC fingerprints and the shared generated
Lean fingerprint. Absolute build metadata can make the raw LLBC
fingerprints differ. [Source replay receipt](source-receipt-windows-x64.json)

The trusted boundary includes rustc and Charon extraction, the restricted
LLBC lowering, the meanings assigned to Rust built-in operations and the
reviewed iterator drivers that supply the four loop inputs. For example,
the parser validates the normal-path `Option` branches and the extracted
values that each iteration writes. It takes the iterations' exact
sequence and pairing from the separately reviewed driver model.
General Rust memory and unwind semantics, compiler output and target
leakage remain separate verification work.

## Charon streaming length and padding replay

Starting from the exact Rust crate's public `digest` symbol, Charon
also produces the reachable `Sha512::update` and `Sha512::finalize` bodies.
The restricted interpreter follows the length cast and guard, checks
that the rejecting branch returns `MessageTooLong` without a data write,
and generates the successful counter expression. It also checks the
order and destinations of the finalizer's marker store, suffix fill,
optional extra compression and reset, big-endian bit-length write,
and final compression. Lean checks the generated terms against the
accepted byte-length domain and FIPS padding, including arbitrary stale
bytes in the underlying 128-byte buffer.
[Source-linked statements](../../../src/crypto/hash/sha512/spec/Sha512StreamSourceRefinement.lean) · [FIPS 180-4 § 5.1.2](https://doi.org/10.6028/NIST.FIPS.180-4)

```sh
python -B tools/verification/sha512/check_stream_source.py --negative-controls
```

Two fresh crate extractions produce identical Lean terms. The source
replay audits nine theorems and recompiles two actual Rust controls,
one rejecting the maximum allowed incoming count and one changing the
padding marker. Both altered proof obligations fail. The replay
accepts the same executable options as the compression replay.
[Windows x64 stream source receipt](stream-source-receipt-windows-x64.json)

The trusted lowering and Rust standard-library contracts cover the
supported integer, slice and byte-conversion operations. The Lean
update theorem attaches the generated gate to the reviewed block
driver, and the finalized digest theorem uses the reviewed encoder.
The update's successful copy-and-compress loop, digest serialization
and public wrapper still have distinct source-refinement obligations.
