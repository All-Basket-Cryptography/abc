# Exact Rust ChaCha20 stream refinement

The verifier selects the public `crate::apply_keystream` entry point and its
reachable functions from `abc-chacha20` on the locked Cargo workspace with
default features disabled. Charon and Aeneas translate the functions twice.
Lean checks the unmodified generated model against independent bitvector
specifications of the RFC 8439 block and stream and audits the theorems'
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
The `theorems` field retains the byte block audit. The `streamModel`
field audits the stream specification and its block-provider composition.
The `sourceStream` field audits eight exact source theorems.
[Historical byte block receipt](../../../docs/status/chacha20-byte-block-ea05776.json)

## Checked scope

The `x86_64-unknown-linux-gnu` extraction uses Charon at
`b104e24fea7d721b71e6c39fd70f26ff20bc0980`, Rust `nightly-2026-08-18`,
and the Aeneas release at `505b6ca35217e7be5c96c3e2f8045edfbdf47291`.
Lean 4.31.0 checks the theorems with the pinned Mathlib backend
and accepts only `propext`, `Classical.choice`, and `Quot.sound`.

`quarter_round_refines` covers all 16 state words for arbitrary state and
four distinct in-range indices. `double_round_refines` checks the eight
indexed calls of a column and diagonal round. `rounds_20_refines` checks
their ten repetitions. `block_words_refines` checks counter installation
and all sixteen feedforward additions for any input state and counter.

`load_word_refines` and `initial_state_refines` check the initial state
and its little-endian inputs. `serialize_refines` checks all 64 output
bytes. `block_refines` and `block_from_bytes_refines` connect the active
byte functions to the RFC's input-to-output block transform for every
key, nonce and counter.

## Stream model

The independent RFC stream specification indexes each input byte by its
quotient and remainder on division by 64. The separate loop model tracks an
incrementing block cursor and makes one logical write per byte. Lean checks
that every prefix transforms just its processed bytes, the cursor advances at
block boundaries, and the preflight accepts exactly the messages for which
every byte has a valid 32-bit counter. Rejection returns the original buffer.
The model covers the empty input and a shortened final block. Its complete
result equals the RFC formula on every byte and the ABC exhaustion policy on
the return status. [RFC 8439 § 2.4.1](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4.1)

Three further theorems connect the logical loop to the exact extracted
block provider. Each provider result is witnessed by successful extracted
`initial_state` and `block` calls. Replacing the model's block provider with
this one preserves the full logical loop result. All eleven new theorems use
the same standard-axiom audit.

For the standalone arithmetic and logical stream proof, use pinned Lean
4.31.0 on `PATH` or available through `elan`.

```sh
python -B src/lean/check.py chacha20
```

## Public source proof

The Rust entry uses bounded indexed loops. The source proof checks its
preflight, byte writes, and inner and outer loops. The decreasing measures
are the unprocessed bytes in the block and in the whole input. At every
iteration the written prefix matches the RFC stream and the remaining bytes
match the original input. Both full and shortened final blocks advance the
offset, and each block counter fits in the 32-bit domain.

`source_apply_keystream_refines` proves termination and equality with the
independent stream specification for every typed key, nonce, initial counter
and finite input slice. The result covers return status, output length and
every byte. `source_apply_keystream_rejects` also proves equality of the
entire returned slice with the original on counter exhaustion. Compiled
code leakage and correspondence of complete authenticated-encryption
implementation paths remain separate.
[Hosted extraction used for local replay](https://github.com/All-Basket-Cryptography/abc/actions/runs/46098562283)

## Stream loop benchmark

On Windows x64 with an Intel Core i7-12700K and Rust 1.92.0
`x86_64-pc-windows-msvc`, one local run compared the former iterator source
at `ca58838` with the indexed source at `b373cfc`. Both were separate
`rustc -O` builds without LTO. Each size used seven alternating A/B
samples, 1,000 warm-up calls per sample, and about 10 MB measured per
sample. Inputs used one fixed key, nonce and counter. Each call operated
on an existing buffer. Times are medians in nanoseconds per call.

| Payload | Former iterator source | Indexed source |
| --- | ---: | ---: |
| 64 bytes | 297.1 | 285.7 |
| 1 KiB | 4,611.8 | 4,427.1 |
| 16 KiB | 73,956.4 | 76,843.3 |

The 16 KiB workload measured 3.9% higher latency in this run. The numbers
characterize this machine, build and workload. [Benchmark source](benchmark.rs)

A second run with the same setup measured 252.9 → 260.4 ns at 64 bytes,
3,925.8 → 4,163.8 ns at 1 KiB, and 62,681.3 → 66,189.7 ns at 16 KiB.
Both runs measured higher latency at 16 KiB.

From the repository root in PowerShell 7.

```powershell
$chachaBench = (New-Item -ItemType Directory -Force .abc/chacha20-stream-benchmark).FullName
git show ca58838:src/crypto/cipher/chacha20/impl/rust/src/lib.rs |
    Set-Content "$chachaBench/previous.rs" -Encoding utf8NoBOM
rustc +1.92.0 --crate-name abc_old --crate-type rlib --edition 2024 -O -o "$chachaBench/libabc_old.rlib" "$chachaBench/previous.rs"
rustc +1.92.0 --crate-name abc_new --crate-type rlib --edition 2024 -O -o "$chachaBench/libabc_new.rlib" src/crypto/cipher/chacha20/impl/rust/src/lib.rs
rustc +1.92.0 --edition 2024 -O --extern "abc_old=$chachaBench/libabc_old.rlib" --extern "abc_new=$chachaBench/libabc_new.rlib" -o "$chachaBench/bench.exe" tools/verification/chacha20/benchmark.rs
& "$chachaBench/bench.exe"
```
