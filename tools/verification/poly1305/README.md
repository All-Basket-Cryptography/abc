# Rust Poly1305 source refinement

The pinned Charon and Aeneas tools translate the reachable bodies rooted at
`crate::absorb_bytes`, `crate::clamped_key` and `crate::key_multiples` from the
portable Rust slice with default features disabled, targeting `x86_64-unknown-linux-gnu`. The
extraction workflow runs the translation twice and publishes `result.json`,
both generated models and the tool logs. The workflow reports extraction
success, and replay checks the Lean theorems.

`Poly1305EncodingRefinement.lean` proves the exact `limbs` helper returns
the first five radix-`2^26` digits of any input `u128` in little-endian order.
`Poly1305SourceRefinement.lean` proves the exact key multiples, five folded
convolution columns, and carry operations using the unbounded integer
arithmetic in `Poly1305GoModel.lean`. Its `source_final_carry_refines` theorem
checks that the carry called by `finalize` normalizes the accumulator and
preserves its residue.

`Poly1305ByteRefinement.lean` checks little-endian loading of 16-byte words
and the RFC clamp of the low key half. For every full 16-byte input block,
`source_absorb_full_block_refines` checks the actual byte-loading and
absorption path against `(h + LE(block) + 2^128) * r mod (2^130 - 5)`.
`source_absorb_padded_final_block_refines` verifies the corresponding
transition for a partial block after the caller has put the marker and
zero padding into the input array. Both block theorems assume a live
accumulator and bounded key limbs with a correct cache, and both preserve
the live-limb invariant.
[RFC 8439 § 2.5.1](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5.1)

The proof assumes the standard Lean model of the Rust integer operations
used by Aeneas. Public key splitting and initialization, streaming chunk
assembly, partial-block padding, final conditional subtraction and tag
emission remain outside the checked source result, as does timing behavior
of the compiled code.

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
[Recorded extraction and theorem audit](source-receipt.json)
