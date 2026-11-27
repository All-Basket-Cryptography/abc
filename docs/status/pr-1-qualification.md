# ABC 0.1 research qualification

The initial commit is in [draft PR #1](https://github.com/All-Basket-Cryptography/abc/pull/1). `main` contains the review baseline README. Candidate assurance fixtures ran successfully on GitHub. The hosted required gate detected that the base does not yet contain independently reviewed assurance code. [Bootstrap run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46043199862)

## SDK consumer evidence

- Node 24.12.0 and headless Chrome 158.0.8127.37 loaded the installed release WASM tarball with SHA-256 `39f158dfca024bb543f012028f80b60e803461ad4108224c0841a093d4f35b81`. Chrome passed the NIST vector, streaming comparison against Web Crypto, independent states, and error and lifecycle checks. TypeScript 5.9.3 resolved the packaged declarations in strict NodeNext mode. Its compiled consumer ran against the same tarball.
- PyO3 0.23.5, Rust 1.92.0 and CPython 3.13.14 produced a Windows x64 wheel and source distribution. Both passed clean offline consumer tests. The source archive built with vendored dependencies in a fresh Cargo cache. [Python package and test commands](../../sdk/python/README.md)
- The Windows `.NET 10.0.404` NuGet package restored from an empty local feed with the ABC package as its sole entry. The external process loaded the `win-x64` DLL and passed the NIST vector, streaming and lifecycle checks. [NuGet package recipe](../../sdk/dotnet/README.md)
- Wasmtime 50.0.3 executed the `wasm32-wasip2` SHA-256 command with no filesystem preopens. Eight vectors passed, including empty input, NIST `abc`, padding boundaries and multiple reads. [WASI package recipe](../../sdk/wasi/README.md)
- Rust 1.92.0 cross-compiled `abc-sha256` for `thumbv7em-none-eabi`. The library is compile-only evidence for a no-OS Cortex-M target. Firmware linking, peripheral integrations, target execution and entropy assumptions have separate scope. [Rust target description](https://doc.rust-lang.org/rustc/platform-support/thumbv7em-none-eabi.html)
- The Android AAR ships `arm64-v8a` and `x86_64` JNI libraries. An independent Kotlin consumer installed and passed on an isolated x86_64 API 36 emulator. The ARM64 evidence is packaging and cross-compilation. [Android evidence](../../sdk/android/EVIDENCE.md)
- A SwiftPM consumer unpacked the built ZIP and passed on macOS 15.8.2 arm64 with Apple Swift 6.1.2. iOS simulator, device and XCFramework targets have separate qualification. [Swift evidence](../../sdk/swift/EVIDENCE.md) · [Hosted Swift job](https://github.com/All-Basket-Cryptography/abc/actions/runs/46045037458/job/140662050455)

The clean Windows plan passed 27 of 29 tasks at commit `e4a5d232bf35f57c812b6192821fb4029fbe2298`. Its two failures were the Linux-bound Aeneas probe and the native Swift consumer. Separate hosted jobs exercise those scopes. Rust and npm research artifacts from commit `92b1ea298fc15e7195d6e8ce893b9f267b636325` were rebuilt in independent local directories and matched their recorded byte digests.

## Formal evidence

Lean 4.31.0 checked the independent SHA-256 model, the complete refinement of the extracted portable Rust SHA-256 implementation, and the SHA3-256 encoding properties. The SHA-256 proof covers one-shot digest, initialization, update, unchanged state on length rejection, and finalization for all accepted chunk partitions. The bounded-addition probe separately reproduced its model and rejected a deliberately altered Rust implementation. [Formal evidence](formal-and-fuzz.md) · [Bounded probe run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46046082715)

## Upstream and research profiles

The exact pinned CPython source closure for HACL* SHA-256 built in the original C, and 34 one-shot and streaming comparisons passed. The local advisory query, source catalog import, checkpoint replay, ChaCha20-Poly1305 and Ed25519 research profiles each have bounded, independent evidence. Secret-bearing production release claims require their own correctness, leakage and review results. [Original C pilot](abc-036-upstream-route.md) · [Research profile scope](../../runtime/research-profiles/README.md)
