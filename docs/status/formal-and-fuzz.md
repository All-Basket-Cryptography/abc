# Formal toolchain and differential fuzzing evidence

Recorded on 2026-11-28 from the ABC Windows workspace. Native runs targeted `x86_64-pc-windows-msvc` using Rust and Cargo 1.92.0, MSVC 14.44.35207, Node.js 24.12.0, and libFuzzer from `libfuzzer-sys` 0.4.13. Coverage files were processed with LLVM tools 21.1.8.

## ABC-003 and ABC-012

| Command | Result |
|---|---|
| `cargo +1.92.0 test --offline --locked --manifest-path formal/probe/rust/Cargo.toml --target-dir .abc/probe-native` | Bounded addition passed the word-boundary matrix. |
| `node formal/probe/fuzz.mjs --native` | Four retained seeds and 10,000 engine invocations. The engine reported zero whole seconds and the process took 58 ms. Widened `u64` addition was the differential oracle. The mutant rejected `0 + 1` with exit `3221226505` and the expected diagnostic. |
| `node formal/probe/check.mjs` | Exit 1. `missing commands: lake, lean; ABC_AENEAS_ROOT is unset`. No LLBC, generated model, Lean output, or proof evidence exists from this run. |
| `curl.exe -I --connect-timeout 6 https://github.com` | Exit 6. `Could not resolve host: github.com`. |
| `git ls-remote https://github.com/AeneasVerif/aeneas HEAD` | `getaddrinfo() thread failed to start`. |
| `wsl --list --verbose` | `Wsl/E_ACCESSDENIED`. |
| `docker version` | Docker client printed its version. Access to the Docker Desktop Linux engine pipe was denied. |

The upstream pin files establish a candidate Aeneas/Charon/Rust/Lean/Mathlib combination in `formal/probe/toolchain-candidate.json`. The full spike and formal probe remain blocked. The check script stores the failure at `.abc/formal-probe/run-UrMNmz/result.json`. Native fuzz commands, seed digests, and the positive and negative logs are at `.abc/probe-fuzz/run-ntlzJF/`. The native run used no sanitizer or coverage counters.

Edge instrumentation on Windows was attempted with cargo-fuzz 0.13.2 on the generic installed nightly and `nightly-2026-03-30`. MSVC failed to resolve `__start___sancov_cntrs`, `__stop___sancov_cntrs`, and the corresponding PC table symbols. The ASan build also failed to link after adding the installed LLVM runtime path because `stl_asan.lib` was unavailable. A supported nightly host remains necessary for the edge-counter mode. The tool itself documents the portability constraints. [Cargo-fuzz project](https://github.com/rust-fuzz/cargo-fuzz)

| Probe input | SHA-256 |
|---|---|
| Rust source | `7e5ff836295bb819b8b685d3fcf330e871de2f9ad93e7aa21715d6e8419dbf18` |
| Fuzz target | `76f59a81038f5f334670b426e6dffdd4e6925446e3bee3f2af6ba0a2f020338a` |
| Lean candidate theorem | `565c0d58c28776e3469bf7a6ac62e9baf298f1ddfdfde38aea82db2f0125eb29` |

## ABC-014 and ABC-016

The independent model, standard mapping, intended refinement statements, and runnable check source are under `algorithms/hash/sha2/sha256/formal/`. The model uses the August 2015 FIPS revision and its included erratum. `Sha256Spec.lean` is `703fa46cf549f57a7fad0647b2e35f3cd981f594506786aebd6ca777d22b943d`. `Checks.lean` is `1f3ce2847c42adced38cdf2e8a3552019aaca421abc0be9b13e8fbff519b2fc7`. Lean compilation, the executable specification checks, and Rust-to-specification refinement remain blocked on the toolchain. [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

## ABC-017

`python abc.py fuzz --implementation sha256-abc-rust-portable --budget 2s --coverage` exited 0. The SHA-256 target used an independent RustCrypto `sha2` 0.10.9 oracle for one-shot, streaming-prefix, and streaming-final comparisons. The 16 retained seeds covered padding and block boundaries and contained messages from zero through 4,096 bytes. libFuzzer reported 124,052 invocations over three whole seconds and 29 MiB peak RSS. The process took 3,054 ms. A copied implementation with one flipped output bit failed on the 56-byte seed with `SHA-256 one-shot mismatch` and exit `3221226505`.

The measured implementation had 195 of 206 covered LLVM source regions and 97 of 103 covered source lines. This run measured source coverage with mutation driven by retained seeds. It used no sanitizer and produced no branch-counter measurements. The engine command, coverage profile and export, corpus digests, and fault log are recorded in `.abc/sha256-fuzz/run-u9WCU7/`. The exact oracle and engine versions are in `algorithms/hash/sha2/sha256/fuzz/Cargo.lock`.

The workspace's existing Cargo cache is read-only. For these runs the necessary registry archive and index files from the lockfile were copied into an ignored, workspace-local Cargo home before using offline mode. The Windows commands ran under the Visual Studio x64 developer environment.
