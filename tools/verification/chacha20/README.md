# ChaCha20 block word refinement

The verifier selects `crate::block_words` from `abc-chacha20` on the locked
Cargo workspace with default features disabled. Charon and Aeneas translate
it twice. Lean checks the unmodified generated model against an independent
bitvector specification of RFC 8439 §§ 2.1–2.3 and audits the theorems'
axioms. [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.1)

On Linux x86-64, set `ABC_AENEAS_ROOT` to the pinned Aeneas checkout with the
release binaries at `bin/aeneas` and `charon/bin/charon`. The dedicated
workflow installs those binaries, Rust and Lean by recorded release pins.
Use `ABC_FORMAL_USE_MATHLIB_CACHE=1` to fetch Mathlib's cache before the Lean
backend build. [Hosted reproduction recipe](../../../.github/workflows/chacha20-model.yml)

```sh
node tools/verification/chacha20/check.mjs
```

The report under `.abc/chacha20-extraction/` records the Rust subject,
proof files, tool versions, binary digests, extracted file digests and
axiom audit. The generated Lean files must match between the two runs.

## Checked scope

The `x86_64-unknown-linux-gnu` extraction uses Charon at
`b104e24fea7d721b71e6c39fd70f26ff20bc0980`, Rust `nightly-2026-08-18`,
and the Aeneas release at `505b6ca35217e7be5c96c3e2f8045edfbdf47291`.
Lean 4.31.0 checks each of the four theorems with the pinned Mathlib backend
and accepts only `propext`, `Classical.choice`, and `Quot.sound`.

`quarter_round_refines` covers all 16 state words for arbitrary state and
four distinct in-range indices. `double_round_refines` checks the eight
indexed calls of a column and diagonal round. `rounds_20_refines` checks
their ten repetitions. `block_words_refines` checks counter installation
and all sixteen feedforward additions for any input state and counter.

Key and nonce decoding, little-endian byte serialization, the public
keystream API and compiled-target leakage remain open.
