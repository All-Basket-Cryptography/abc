# Portable Rust GHASH source refinement

Charon selects the `multiply` function used by the portable Rust
AES-256-GCM authenticator. The locked Cargo workspace uses no default
features. The runner extracts the function twice and requires identical
generated Lean modules. It records the source inputs and both raw LLBC
digests separately. Local compiler paths can differ in the raw files.
[Rust source](../../../src/crypto/aead/aes256-gcm/impl/rust/src/lib.rs)
· [Toolchain pins](../probe/toolchain-candidate.json)

`translate.py` translates the selected structured LLBC loop and its
scalar assignments. It validates types, the Boolean control-flow
shape and the standard `u128::wrapping_sub` call. Checked subtraction
and shift operations produce explicit guards in Lean. Storage
annotations and fake reads on the validated scalar locals have no
effect on the translated values. Unsupported statements, operands,
projections and calls fail validation. The code relies on Charon's
extraction and the supported Rust-to-Lean semantics implemented in the
translator.

The checked theorem `source_multiply_returns_nist` covers all pairs
of 128-bit values. It proves the extracted loop terminates within the
extracted 128-round bound, takes no panic branch and returns the
SP 800-38D Algorithm 1 result. Supporting theorems identify the round
and loop behavior. Lean checks the three results with only the
standard axioms `propext`, `Classical.choice` and `Quot.sound`.
[Proof source](GhashSourceRefinement.lean)
· [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

This result covers the field multiplication called during GHASH.
Proofs for the Rust GHASH wrapper, the AES provider, full source-level
seal and open and compiler-level leakage require separate work.
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
`result.json` under `.abc/aes256-gcm-extraction/`. With
`--check-mutant`, it changes the reduction literal in one LLBC
copy and requires Lean to reject the changed multiplication at the
round equality. The project sources remain untouched during replay.
[Recorded Windows x64 proof and source digests](source-receipt-windows-x64.json)
