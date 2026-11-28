# Rust Poly1305 source refinement

The pinned Charon and Aeneas tools translate the reachable bodies rooted at
`crate::absorb_encoded` and `crate::key_multiples` from the portable Rust slice
with default features disabled, targeting `x86_64-unknown-linux-gnu`. The
extraction workflow runs the translation twice and publishes `result.json`,
both generated models and the tool logs. The workflow reports extraction
success, and replay checks the Lean theorems.

`Poly1305EncodingRefinement.lean` proves the exact `limbs` helper returns
the first five radix-`2^26` digits of any input `u128` in little-endian order.
`Poly1305SourceRefinement.lean` proves the exact key multiples, five folded
convolution columns, and carry operations. The combined theorem
`source_absorb_polynomial_step` checks that the exact `absorb_limbs` helper
succeeds and preserves the live-limb invariant while taking one
`(h + m) * r mod (2^130 - 5)` step. Its hypotheses are a live accumulator,
key and decoded message digits below `2^26`, and correct cached multiples.
The proof reuses the unbounded integer arithmetic in `Poly1305GoModel.lean`.
[RFC 8439 § 2.5.1](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5.1)

The byte-loading and high-bit path through `absorb_encoded`, key clamping,
stream chunking, final tag emission and compiled timing behavior remain
outside the checked source result.

## Replay

Start with the extraction artifact for a checkout with identical extraction
inputs, or generate it on the pinned Linux host by running
`node tools/verification/poly1305/check.mjs` with `ABC_AENEAS_ROOT` set to
the pinned checkout. Use the directory inside the artifact that contains
`result.json`, `first` and `second` as the replay argument.

Use Lean 4.31.0 and the compiled Lean libraries from the pinned Aeneas
checkout and all its Lake dependencies. If those libraries are already
built, replay uses them directly on either Windows or Linux. Set `LEAN_PATH`
to the backend's `.lake/build/lib/lean` and each package directory's
`.lake/build/lib/lean`, separated by the OS path separator. Set
`ABC_LEAN_BIN` to the Lean executable if `lean` on `PATH` differs from the
pin in [`toolchain-candidate.json`](../probe/toolchain-candidate.json).

```sh
node tools/verification/poly1305/replay.mjs /path/to/artifact/run-directory
```

The runner checks input hashes against the current checkout, compares both
generated models with the extraction receipt, compiles the actual
generated files and the proof modules, and checks the theorem axiom
reports. It saves the result and compiler logs under `.abc/poly1305-replay`.
[Recorded extraction and eight-theorem audit](source-receipt.json)
