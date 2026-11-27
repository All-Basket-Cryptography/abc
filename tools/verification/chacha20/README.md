# ChaCha20 quarter-round refinement

The verifier selects `crate::quarter_round` from `abc-chacha20` on the locked
Cargo workspace with default features disabled. Charon and Aeneas translate
it twice. Lean checks the unmodified generated model against an independent
bitvector specification of RFC 8439 §§ 2.1–2.2 and audits the theorem's
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

The local `x86_64-pc-windows-msvc` run used Charon at
`b104e24fea7d721b71e6c39fd70f26ff20bc0980`, Rust `nightly-2026-08-18`,
the Linux Aeneas release at `505b6ca35217e7be5c96c3e2f8045edfbdf47291`, and
Lean 4.31.0 with the pinned Mathlib backend. Two translations produced
matching `Types.lean` and `Funs.lean` files without external declarations.
Lean checked `Abc.Refine.ChaCha20.quarter_round_refines` with `propext`,
`Classical.choice`, and `Quot.sound`.

The measured Rust source SHA-256 is
`6609fa40b99d655f2b7bcb0922b3df4b6c09363ffcdc1fa51ff4c4ee62e5bde4`.
The matching generated `Funs.lean` files from that local target have
SHA-256 `bec7838c17ff20f0d6cb2e73272fdb668c09396bfb220992649c6b921bc4e1e9`.
The generated files contain the source location and the verifier records
their digests per target and checkout.

The theorem covers all 16 output words of a single quarter round for
arbitrary state and four distinct in-range indices. Block rounds, the
counter and keystream API, and compiled-target leakage remain separate
verification work.
