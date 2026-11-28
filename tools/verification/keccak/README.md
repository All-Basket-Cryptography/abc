# Rust Keccak source refinement

The replay starts Charon at the Rust `absorb_rate_block` entry point and
lowers its reachable Keccak-p[1600,24] implementation. It traverses the
actual array, slice, enumerate and zip loops, checks all scalar index
arithmetic and accesses, and generates a symbolic expression for each
of the 25 output lanes. The round expressions retain arbitrary input
lanes and an arbitrary round constant. The outer iterator supplies the
24 constants in the order extracted from the crate.

Lean checks every generated round expression and all 24 constants
against the FIPS 202 formulas. It proves the permutation agrees for all
1,600 input bits, and proves that little-endian absorption into the first
17 lanes followed by the permutation agrees for every 136-byte block.
The sponge theorem composes the source-derived absorption and permutation
with the existing rate-output and domain-padding models for SHA3-256 and
SHAKE256. It quantifies over arbitrary initial lane values, finite input
and output blocks, and all legal tail lengths.
[Lean statements](../../../src/crypto/hash/keccak-p1600/spec/KeccakSourceRefinement.lean) · [FIPS 202 §§ 3–6](https://csrc.nist.gov/pubs/fips/202/final)

Run from the repository root with Charon at the repository pin, its
Rust toolchain, the LLVM linker, and Lean 4.31.0 available. The options
`--charon` and `--lean` accept explicit executable paths.

```sh
python -B tools/verification/keccak/check_source.py --negative-controls
```

The replay compares the generated Lean from two independent crate
extractions and audits nine theorems. The three negative controls
recompile real Rust changes to theta's rotation, the absorb byte order,
and one iota constant. Each must fail its corresponding Lean equality.
[Windows x64 receipt](source-receipt-windows-x64.json)

The trusted boundary includes rustc, Charon, the restricted LLBC lowering
and the Rust integer and collection contracts used during lowering.
The proof covers the Keccak crate's normal-path permutation and block
absorption. The wrapper replay below covers SHA3-256's byte digest and
SHAKE256's byte-oriented streaming and one-shot APIs. General Rust memory
and unwind semantics, machine code and timing are separate verification obligations.
The Rust release suites exercise the two wrappers on known answers,
rate boundaries and repeated or late output reads.

```sh
cargo +1.92.0 test --manifest-path tools/build/rust/Cargo.toml --release --locked --offline \
  -p abc-keccak-p1600 -p abc-sha3-256 -p abc-shake256
```

## SHA3-256 and SHAKE256 Rust wrappers

The wrapper replay starts at the public SHA3-256 `digest` and SHAKE256 `xof`
symbols. For SHA3-256 it checks the zero-state constructor, the full-block
iterator's absorb call, the final block and all 32 serialized bytes. It
models Rust's `as_chunks` as the sequence of complete 136-byte blocks and
its short tail. For SHAKE256 it checks the constructor, both incremental
input paths, the `xof` call sequence, `finalize`, and `Reader::encode_block`.
The input driver checks the computed prefix-copy window, the completion
branch, the ordered full blocks and the final short-tail copy. The reader replay
checks the two Rust loop conditions, the refresh-and-encode order, the span
bound, both copy endpoints, the next offset and the remaining output slice.

The lowering exhausts all 136 legal tail lengths with symbolic bytes and
checks the suffix and high padding bit against the generated form. At a
135-byte tail the two markers occupy the same byte. SHAKE256's check uses
arbitrary symbolic stale bytes outside the pending prefix. The generated
wire mapping comes from the actual chunk writes and lane byte conversions.
Lean proves every SHA3-256 digest bit equals the FIPS sponge result for any
finite sequence of full blocks and any legal tail. It proves the SHAKE256
finalizer's lanes, first output block and zero cursor agree with FIPS.
The SHAKE256 trace theorem applies to any finite input and read partition.
It includes empty updates, empty reads and states paused exactly at a rate
boundary. The byte-valued partition theorem equates the streaming outputs
with `xof` on the concatenated input and total requested length.
[Wrapper proofs](../../../src/crypto/hash/keccak-p1600/spec/KeccakWrapperSourceRefinement.lean) · [Reader proofs](../../../src/crypto/hash/keccak-p1600/spec/KeccakReaderSourceRefinement.lean) · [Absorber and XOF proofs](../../../src/crypto/hash/keccak-p1600/spec/KeccakAbsorbSourceRefinement.lean) · [FIPS 202 §§ 4 and 6](https://csrc.nist.gov/pubs/fips/202/final)

```sh
python -B tools/verification/keccak/check_wrappers.py --negative-controls
```

The replay checks 24 theorems and recompiles seven Rust mutations. Lean
rejects the altered domain bytes, wire byte order, refresh condition,
copy bound and constructor lanes. The lowering rejects an `xof` mutation
that finalizes a fresh context after updating another context. The replay
trusts the Rust standard library's slicing, iteration, copying and byte
conversion contracts.
[Windows x64 wrapper receipt](wrapper-receipt-windows-x64.json)
