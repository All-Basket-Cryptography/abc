# Rust-to-Lean engineering probe

The probe exposes one bounded word operation, `bounded_add`. Its intended theorem covers every input pair whose mathematical sum fits in a 32-bit unsigned word. This module is isolated from the cryptographic registry and SDKs.

## Native checks

```sh
cargo +1.92.0 test --locked --manifest-path formal/probe/rust/Cargo.toml --target-dir .abc/probe-native
node formal/probe/fuzz.mjs --native
```

Native fuzzing requires a C++ compiler supported by Cargo. Windows MSVC builds require the compiler, linker, and SDK environment. The driver retains four seed inputs, runs libFuzzer against widened arithmetic, saves the actual command and output, and rebuilds a scratch copy with a deliberately incorrect return value. It requires the mutated program to fail with the differential diagnostic. The native run uses neither sanitizer instrumentation nor edge counters.

Run `node formal/probe/fuzz.mjs` on a provisioned nightly host with `cargo-fuzz` to request edge instrumentation. The command fails if the engine reports zero coverage modules. Results appear in `.abc/probe-fuzz/`.

## Formal reproduction

`toolchain-candidate.json` pins the upstream compatibility declarations. ABC has yet to execute the pinned pipeline. The Aeneas source identifies the Charon and Lean pins and requests Mathlib `v4.31.0`. The Charon checkout pins `nightly-2026-08-18` with its required components. [Aeneas Charon pin](https://github.com/AeneasVerif/aeneas/blob/505b6ca35217e7be5c96c3e2f8045edfbdf47291/charon-pin) [Aeneas Lean backend](https://github.com/AeneasVerif/aeneas/tree/505b6ca35217e7be5c96c3e2f8045edfbdf47291/backends/lean) [Charon Rust toolchain](https://github.com/AeneasVerif/charon/blob/b104e24fea7d721b71e6c39fd70f26ff20bc0980/charon/rust-toolchain) [Mathlib release](https://github.com/leanprover-community/mathlib4/releases/tag/v4.31.0)

Build the pinned Aeneas checkout and its Charon checkout using the upstream OCaml dependencies and `make setup-charon` followed by `make` on a provisioned POSIX host. Install the pinned Lean toolchain and enable the matching `lean` and `lake` commands. [Pinned build instructions](https://github.com/AeneasVerif/aeneas/blob/505b6ca35217e7be5c96c3e2f8045edfbdf47291/README.md#installation--build)

```sh
ABC_AENEAS_ROOT=/absolute/path/to/pinned/aeneas node formal/probe/check.mjs
```

The driver checks checkout revisions and tracked modifications, re-extracts the source twice in fresh Cargo target directories, compares the generated Lean bytes, and checks the Lean axiom report. The negative fixtures exercise a transitive `sorry`, a custom axiom, native evaluation, and an altered Rust result. Each run uses a fresh directory under `.abc/formal-probe/` for commands, digests, and checker output. The local checker is for the repository's research probe. Independent proof comparison, sandboxed checking, and evidence for compiler or machine-code claims require additional work. [Lean proof validation](https://lean-lang.org/doc/reference/4.31.0/ValidatingProofs/)
