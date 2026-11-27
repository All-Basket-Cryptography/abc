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

The table records the initial tool availability. A later authorized download resolved the Windows Lean dependency. The upstream pin files and checked-out Aeneas and Charon revisions match `formal/probe/toolchain-candidate.json`. The installed Alpine WSL registration has no backing disk and Windows native OCaml packaging excludes Aeneas's `core_unix` dependency. The pinned hosted research workflow provisions the exact Aeneas release on an ephemeral Linux runner. [Aeneas build requirements](https://github.com/AeneasVerif/aeneas/blob/505b6ca35217e7be5c96c3e2f8045edfbdf47291/README.md#installation--build) [OCaml core_unix platform support](https://opam.ocaml.org/packages/core_unix/) [Pinned Aeneas release](https://github.com/AeneasVerif/aeneas/releases/tag/nightly-2026.09.09-505b6ca)

The native fuzz commands, seed digests, and positive and negative logs are at `.abc/probe-fuzz/run-ntlzJF/`. The native run used no sanitizer or coverage counters. The verified Lean release also ran the isolated negative axiom fixture from `formal/probe/RejectedProof.lean`. Lean reported `sorryAx` for the transitive case, `Abc.Probe.Fixtures.unapproved` for the custom axiom, and a generated native-evaluation axiom for `native_decide`. The log is `.abc/formal-tools/lean-negative-axioms.log`.

The native Rust-to-LLBC step ran successfully. Charon `0.1.254` at `b104e24fea7d721b71e6c39fd70f26ff20bc0980` was built from the pinned source and lockfile with `nightly-2026-08-18`, rustc `1.100.0-nightly` at `8fa1c96cfd489e4c27654c144ae871ce2c4db6c6`, and `rustc-dev` for `x86_64-pc-windows-msvc`. From fresh scratch Cargo crates, `charon cargo --preset=aeneas --dest-file <absolute-path>` emitted the arithmetic probe and the portable SHA-256 implementation. Charon selected rustc's default sysroot after reporting the missing Miri component. `charon pretty-print` read both output files and showed the expected source functions. [Pinned Charon source](https://github.com/AeneasVerif/charon/commit/b104e24fea7d721b71e6c39fd70f26ff20bc0980)

| Native LLBC output in `.abc/formal-tools/` | Bytes | SHA-256 |
|---|---:|---|
| `bounded-add.llbc` | 97,453 | `6bf9863228de6c3c257f03a7a9bf8127aecbfe3e6bb5c88c04489711f04eb0f0` |
| `sha256-portable.llbc` | 1,251,426 | `fdf27cfb0a014aeceee2e10c72366021c723122f8298e65c305e5af80488a4fd` |

The scratch mutant extracted successfully as `bounded-mutant.llbc` with digest `2c9b119b76a77e4db8ea12cf60f03db4046ff79d52a1716c8270e51f47de77d8`. Charon's decoded output contains a checked addition for the original, while the mutant directly returns `left`. The hosted workflow exercises the Lean rejection of the mutated model.

The first release-based Ubuntu run completed Rust extraction and independent re-extraction, Aeneas translation, byte comparison of the generated Lean files, and the Lean model build. Its handwritten proof reached the reduced goal and an identical local hypothesis. Lean rejected the declaration because that hypothesis had not been applied. The correction closes that goal with `assumption`. The run's generated `Funs.lean` has digest `ac49aff2f399d7e587136b6f1cf38a031ea59c35623aa9963a70deff217dfb1a`. [Hosted run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46045037475) [Untrusted diagnostic archive](https://github.com/All-Basket-Cryptography/abc/actions/runs/46045037475/artifacts/15222386197)

The corrected Ubuntu advisory run passed on commit `05e496f6f2202950ddc0ac26c546f90987d53f74`. It used the checksum-verified Aeneas `nightly-2026.09.09-505b6ca` release, Charon `b104e24fea7d721b71e6c39fd70f26ff20bc0980`, and Rust `1.100.0-nightly` at `8fa1c96cfd489e4c27654c144ae871ce2c4db6c6` for `x86_64-unknown-linux-gnu`. Lean was `4.31.0` at `68218e876d2a38b1985b8590fff244a83c321783`, and Lake resolved Mathlib `fabf563a7c95a166b8d7b6efca11c8b4dc9d911f`. [Passing hosted job](https://github.com/All-Basket-Cryptography/abc/actions/runs/46046082715/job/140665604933)

| Check | Observed result |
|---|---|
| Independent re-extraction | Both passes generated `Funs.lean` at `ac49aff2f399d7e587136b6f1cf38a031ea59c35623aa9963a70deff217dfb1a` and `Types.lean` at `ac29ccd3a92820c31988b3ee721b1c6f35d6d7e7801d82021934da1806bd766a`. |
| Positive proof | Lean accepted `Abc.Probe.boundedAddRefines`. Its axiom closure contained `propext`, `Classical.choice`, and `Quot.sound`. |
| Transitive `sorry` fixture | Lean reported `sorryAx`, and the probe's axiom allowlist rejected it. |
| Custom axiom fixture | Lean reported `Abc.Probe.Fixtures.unapproved`, and the allowlist rejected it. |
| Native evaluation fixture | Lean reported `Abc.Probe.Fixtures.nativeEvaluation._native.native_decide.ax_1_1`, and the allowlist rejected it. |
| Changed implementation | The mutant's `Funs.lean` at `439bed5716ca22d3a62e26ab051adba8c74d2eaa71f12f830c025506495f210f` compiled. The unchanged proof failed with `Eq is not a supported spec statement` after the checked addition was replaced with a direct return of `left`. |

The advisory archive SHA-256 is `555fc40662fc1d6b8cf4a9f04cb800e4f22fb24a4b7765d25a67a903afeed373`. This run establishes the isolated bounded-addition probe on the pinned Linux toolchain. Full SHA-256 implementation refinement and trusted release evidence remain open. [Untrusted advisory diagnostics](https://github.com/All-Basket-Cryptography/abc/actions/runs/46046082715/artifacts/15222127448)

Edge instrumentation on Windows was attempted with cargo-fuzz 0.13.2 on the generic installed nightly and `nightly-2026-03-30`. MSVC failed to resolve `__start___sancov_cntrs`, `__stop___sancov_cntrs`, and the corresponding PC table symbols. The ASan build also failed to link after adding the installed LLVM runtime path because `stl_asan.lib` was unavailable. A supported nightly host remains necessary for the edge-counter mode. The tool itself documents the portability constraints. [Cargo-fuzz project](https://github.com/rust-fuzz/cargo-fuzz)

| Probe input | SHA-256 |
|---|---|
| Rust source | `7e5ff836295bb819b8b685d3fcf330e871de2f9ad93e7aa21715d6e8419dbf18` |
| Fuzz target | `76f59a81038f5f334670b426e6dffdd4e6925446e3bee3f2af6ba0a2f020338a` |
| Lean candidate theorem | `46a891e4f8ff019a0f9469b5c90fab0e1ef403f05e85b69b8f3fa8d95af78966` |

## ABC-014 and ABC-016

The independent model, standard mapping, intended refinement statements, and runnable check source are under `algorithms/hash/sha2/sha256/formal/`. The model uses the August 2015 FIPS revision and its included erratum. [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

`python foundation/lean/check.py sha256` exited 0 using the official Lean 4.31.0 Windows release, commit `68218e876d2a38b1985b8590fff244a83c321783`. The downloaded archive matched the published SHA-256 `9d482ee0c1af858cddb5bfb582969499a787caf9c4f953bc81d512da6dcc12c7`. Lean compiled the specification and checked its abstract stream theorems for accepted updates, rejection outside the length domain, and finalization after an accepted update. The three theorems have only `propext` and `Quot.sound` in their combined axiom dependencies. Executable empty and `abc` vectors, streaming, the padding boundary matrix, and the maximum byte length check passed. The log is `.abc/formal-tools/sha256-lean.log`. Rust-to-specification refinement is a separate open task. [Official Lean release](https://github.com/leanprover/lean4/releases/expanded_assets/v4.31.0)

The SHA-256 LLBC contains the `compress`, `update`, `finalize`, and `digest` bodies for the checked source digest. It includes external operations such as `core::slice::as_chunks` and `as_chunks_mut` as opaque declarations. Completing Rust refinement requires checking their generated Lean models and the reachable-state relation. The LLBC stage does not establish any of those properties.

A scratch copy of the specification with its first round constant changed from `0x428a2f98` to `0x428a2f99` compiled successfully. The original vector driver rejected the changed digest with exit 1 and `SHA-256 empty-message vector mismatch`. The transcript is `.abc/formal-tools/spec-mutant/result.log`.

| Checked input | SHA-256 |
|---|---|
| `Sha256Spec.lean` | `71fa57c2b3eba86ebef15199818c12f78aed9e43582bdbd0bdacc21bd3e6ad2d` |
| `Checks.lean` | `90762aeff4f5635327799c56fe5f1ec6edad867cbcb2ff8ca8c4ce0b4bc2c5dc` |
| Shared `Encoding.lean` | `1e4e51f3430cd6262cabedc9b6a7db80bb8e6f2a4f12af64a842f5e4ef7c32e9` |

## ABC-017

`python abc.py fuzz --implementation sha256-abc-rust-portable --budget 2s --coverage` exited 0. The SHA-256 target used an independent RustCrypto `sha2` 0.10.9 oracle for one-shot, streaming-prefix, and streaming-final comparisons. The 16 retained seeds covered padding and block boundaries and contained messages from zero through 4,096 bytes. libFuzzer reported 124,052 invocations over three whole seconds and 29 MiB peak RSS. The process took 3,054 ms. A copied implementation with one flipped output bit failed on the 56-byte seed with `SHA-256 one-shot mismatch` and exit `3221226505`.

The measured implementation had 195 of 206 covered LLVM source regions and 97 of 103 covered source lines. This run measured source coverage with mutation driven by retained seeds. It used no sanitizer and produced no branch-counter measurements. The engine command, coverage profile and export, corpus digests, and fault log are recorded in `.abc/sha256-fuzz/run-u9WCU7/`. The exact oracle and engine versions are in `algorithms/hash/sha2/sha256/fuzz/Cargo.lock`.

The workspace's existing Cargo cache is read-only. For these runs the necessary registry archive and index files from the lockfile were copied into an ignored, workspace-local Cargo home before using offline mode. The Windows commands ran under the Visual Studio x64 developer environment.
