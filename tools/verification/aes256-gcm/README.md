# Portable Rust GHASH and authentication gate refinement

Charon extracts the portable Rust AES-256-GCM `seal_in_place` and
`open_in_place` call graphs with evaluated Rust constants.
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
`pack_lengths`, `finish_tag` and `tags_match`. It validates types, the
Boolean loop shape, calls between these functions and the standard
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
serializes this word to the reference tag.

The length guard translates both comparisons and their result branches.
The validator traces the lengths of the full AAD and payload slices into
that guard in both APIs, and checks that a rejection returns before AES
setup and any payload write. Lean verifies the exact limits and that a
payload length error takes precedence when both lengths exceed their limits.

The CTR checker traces `chunks_mut(16).enumerate()` to the index
cast and checked addition in `apply_payload` and checks the counter's use
in the call to `encrypt_counter`. It validates the nonce prefix and the
big-endian counter suffix copied into the same array passed to AES. It
traces the AES output through `zip` to each byte assignment in the
current chunk. Lean proves that every admitted payload byte uses the
expected counter from 2 through `0xffffffff` without truncation or
overflow. It proves the complete chunk and partial-chunk transform agrees
with NIST GCTR under the AES block contract. The compiler's evaluated
constants and Rust's array, slice, iterator and `Result` contracts
provide the corresponding source operations.

The open-path validator checks dataflow from `authenticate` and the full
received tag into the comparison, the comparison result into the branch,
and the complete mutable ciphertext slice into the accepted `apply_payload`
call. The failed branch returns `AuthenticationFailed` before that call.
Lean proves that the extracted XOR/zero comparison is equivalent to byte
equality on the entire tag. For any payload transformation, a mismatched
tag preserves ciphertext and a matching tag reaches the transformation.
The composed open theorem uses the extracted CTR and the GHASH block
model to reach the NIST outcome. Lean checks 27 results with only
`propext`, `Classical.choice` and `Quot.sound`.
[Proof source](GhashSourceRefinement.lean)
· [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

The tag gate relies on the standard library's functional contracts for
`u128::from_be_bytes` and `black_box`. The byte-to-block bridge uses the
Lean `sourceBlocks` model. Source proofs for GHASH slice traversal,
padding and byte conversions, the concrete AES provider and the
end-to-end source connection for seal remain open. Timing and compiler
leakage require separate evidence.
[Rust `black_box`](https://doc.rust-lang.org/core/hint/fn.black_box.html)
· [Rust slice `chunks_mut`](https://doc.rust-lang.org/std/primitive.slice.html#method.chunks_mut)
· [Rust iterator `enumerate`](https://doc.rust-lang.org/core/iter/trait.Iterator.html#method.enumerate)
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
and 60-byte ciphertext in NIST GCM-AES256 example 5. Further controls
reverse tag comparison, swap the open branch destinations, reject the
largest valid payload length and start the CTR payload at the reserved
tag counter. The CTR controls also reverse the counter byte order and
replace the byte XOR with OR. The release test checks rejection and
ciphertext preservation for each of the 128 single-bit tag changes in
example 5.
[NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)
[Recorded Windows x64 proof and source digests](source-receipt-windows-x64.json)

## Windows x64 code generation

The Rust 1.92.0 release assembly for portable `open_in_place` reads both
64-bit halves of the received tag, byte-swaps them, XORs each with the
corresponding computed half, and ORs both results before the tag-dependent
branch. The branch skips the payload write on mismatch. The observed
comparison region has no `memcmp` call or branch on a partial comparison.
The emitted file had SHA-256
`9e7ddd90429a1240873133667bb2a38ab34860667cd5ea816ef776bb4f10d098`.
This inspection covers the recorded compiler, build and comparison region.
Other targets and effects such as memory erasure, speculation and timing
remain separate verification obligations.

```sh
cargo +1.92.0 rustc --release --locked --offline --manifest-path tools/build/rust/Cargo.toml -p abc-aes256-gcm --lib -- --emit=asm
```
