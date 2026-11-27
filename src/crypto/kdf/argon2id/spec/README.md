# Argon2id v1.3

The portable Rust core implements the Argon2id type and version `0x13`
from RFC 9106. It uses the repository's portable BLAKE2b core for the
parameter and initial-block hashing and the variable-length tag. The memory
matrix uses Argon2id's data-independent addressing for the first two slices
of pass zero and data-dependent addressing thereafter. Lanes are computed
serially, with the same slice boundaries as a parallel implementation.
[RFC 9106 §§ 3.1–3.6](https://www.rfc-editor.org/rfc/rfc9106.html#section-3)

## API profile

`Parameters::new(memory_kib, iterations, lanes)` takes positive passes,
1–`2^24 - 1` lanes and a memory request of at least eight 1 KiB blocks
per lane. Each parameter fits in a 32-bit unsigned integer. The initial
digest includes the original request, while `workspace_blocks()` returns
the rounded count of blocks used. A workspace must fit in a Rust slice.

`derive` writes a raw tag of 4–`2^32 - 1` bytes to a caller-supplied
slice using a caller-supplied array of 1 KiB blocks. Password, salt,
secret and associated data each have a 32-bit length field. This profile
requires a salt of at least eight bytes. Secret and associated data are
optional and can be supplied as empty slices. Parameter, length and
workspace admission precede all writes. Extra workspace blocks are
untouched. The caller owns cost limits and erasure of password-derived
material in the workspace. RFC 9106 recommends a unique 16-byte salt
for password hashing.
[RFC 9106 §§ 3.1–3.2](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.1)

## Conformance

Run from the repository root with Rust 1.92.0. The independent
comparison uses Node 24.7.0 or later with OpenSSL Argon2 enabled.

```sh
cargo +1.92.0 test --locked --offline --manifest-path tools/build/rust/Cargo.toml -p abc-argon2id
node src/crypto/kdf/argon2id/spec/verify.mjs
```

The Windows x64 run passed four Rust tests and 110 independent comparisons
against Node 24.12.0 with OpenSSL 3.5.4. The RFC 9106 § 5.3 test includes
secret and associated data, the initial digest, all published checkpoint
words after each pass, and the final tag. The oracle cases exercise
non-aligned memory requests, repeated passes, different lane counts,
129-block segments to reach a second address batch, and tags of up to
257 bytes. Unit tests exercise encoded length bounds, workspace sizing,
and unchanged buffers after invalid requests. The library also passed
compile checks on Rust 1.92.0 for `wasm32-wasip2` and
`thumbv7em-none-eabi`.
[RFC 9106 § 5.3](https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3)

## Checked bounds

Lean 4.31.0 checks the memory rounding and block layout, the initial and
fill indices, and the 64-bit arithmetic used to choose the reference
column. The model states the capacity and input conditions used by the Rust
code and proves the bounds over natural numbers.

```sh
lean -DwarningAsError=true src/crypto/kdf/argon2id/spec/Argon2idBounds.lean
```

Rust extraction and source-to-model refinement remain open, along with
side-channel assessment, key-material erasure and target-specific performance
measurements.
