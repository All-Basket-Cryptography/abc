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
absorption. The Rust SHA3-256 and SHAKE256 public wrappers' buffering,
domain-padding writes and wire-output drivers, general Rust memory and
unwind semantics, machine code and timing are separate verification
obligations. The Rust release suites exercise the two wrappers on known
answers, rate boundaries and repeated or late output reads.

```sh
cargo +1.92.0 test --manifest-path tools/build/rust/Cargo.toml --release --locked --offline \
  -p abc-keccak-p1600 -p abc-sha3-256 -p abc-shake256
```
