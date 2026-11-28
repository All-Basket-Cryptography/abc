# Portable Rust GHASH source refinement

Charon extracts the portable Rust AES-256-GCM `authenticate` call graph.
The translator checks the local call sequence in `authenticate`, from the
two padded updates to length packing, the tag-mask counter and final tag
computation. It checks both call sites of the block operation in
`hash_padded`. The locked Cargo workspace uses no default features.
The runner performs two extractions and requires identical generated Lean
modules. It records the source inputs and both raw LLBC digests separately.
Local compiler paths can differ in the raw files.
[Rust source](../../../src/crypto/aead/aes256-gcm/impl/rust/src/lib.rs)
· [Toolchain pins](../probe/toolchain-candidate.json)

`translate.py` translates the scalar bodies of `multiply`, `hash_block`,
`pack_lengths` and `finish_tag`. It validates types, the Boolean loop
shape, calls between these functions and the standard
`u128::wrapping_sub` call. Checked subtraction, multiplication and
shifts produce explicit guards in Lean. Storage annotations and fake
reads on the validated scalar locals have no effect on the translated
values. Unsupported statements, operands, projections and calls in
these scalar bodies fail validation. The trusted translation boundary
includes Charon and the Rust-to-Lean semantics in the translator.

The checked theorem `source_multiply_returns_nist` covers all pairs
of 128-bit values. It proves the extracted loop terminates within the
extracted 128-round bound, takes no panic branch and returns the
SP 800-38D Algorithm 1 result. The checked composition folds the extracted
block operation over the modeled AAD and ciphertext blocks. It includes
the exact packed length word and final tag-mask XOR. For byte lengths in
the SP 800-38D bit-length domain, the resulting tag word agrees with the
standard's padded transcript for every AAD, ciphertext, hash key and
tag mask. A separate result supplies the two required AES block values and
serializes this word to the reference tag. Lean checks the eleven results
with only `propext`, `Classical.choice` and `Quot.sound`.
[Proof source](GhashSourceRefinement.lean)
· [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

The byte-to-block bridge uses the Lean `sourceBlocks` model. A source-level
proof still needs to connect Rust's slice traversal, zero padding and
byte conversions to that bridge, and prove the concrete AES provider and
the full `seal_in_place` and `open_in_place` paths. The checked semantics
describe functional results. Timing and compiler leakage remain open.
[Composition model and scope](../../../src/crypto/aead/aes256-gcm/spec/README.md)

## Reproduce

Use Charon at `b104e24fea7d721b71e6c39fd70f26ff20bc0980`,
Rust `nightly-2026-08-18` and Lean 4.31.0. Run from the repository root
with the locked Cargo dependencies in the local cache. Charon and
Lean may be selected through `PATH` or via `--charon` and `--lean`.
The checked target is Windows x64 MSVC.

```sh
python -B tools/verification/aes256-gcm/check.py --check-mutant
cargo +1.92.0 test --release --locked --offline --manifest-path tools/build/rust/Cargo.toml -p abc-aes256-gcm
```

The runner writes the two extracted models, an axiom audit and
`result.json` under `.abc/aes256-gcm-extraction/`. With `--check-mutant`,
it changes the reduction literal in one LLBC copy and requires Lean to
reject the round equality. A second mutation reverses the length word's
shift. Lean must reject the footer value computed from the 20-byte AAD
and 60-byte ciphertext in NIST GCM-AES256 example 5.
[NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)
[Recorded Windows x64 proof and source digests](source-receipt-windows-x64.json)
