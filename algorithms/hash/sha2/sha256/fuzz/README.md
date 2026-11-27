# SHA-256 differential fuzzing

```sh
python abc.py fuzz --implementation sha256-abc-rust-portable --budget 5s
```

The harness feeds messages and in-band chunk instructions to ABC's portable Rust API. It compares one-shot, intermediate clone/finalize, and final streaming digests against RustCrypto `sha2` v0.10.9. The independent oracle and engine are confined to the fuzz workspace. The seed corpus covers padding and block boundaries through 4,096 bytes. A scratch rebuild flips the first digest bit and must fail with the expected mismatch. [RustCrypto API and source](https://docs.rs/sha2/0.10.9/sha2/)

The runner preserves seed inputs, sets per-input timeout and RSS limits, and records actual engine time, invocation count, source and harness digests, corpus digests, and fault output under `.abc/sha256-fuzz/`. libFuzzer reports elapsed whole seconds and can run into the next second at the budget boundary.

The Windows CLI uses native libFuzzer. With `--coverage`, the Windows runner also builds with LLVM source instrumentation and exports covered region, line, and function counts. This option requires `llvm-profdata` and `llvm-cov` compatible with the Rust compiler's LLVM version. The non-Windows CLI requests edge counters using the pinned nightly and `cargo-fuzz`. The native and edge modes use the same oracle and corpus. [Rust source-based coverage](https://doc.rust-lang.org/rustc/instrument-coverage.html)
