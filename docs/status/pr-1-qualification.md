# ABC 0.1 research qualification

The initial commit is in [draft PR #1](https://github.com/All-Basket-Cryptography/abc/pull/1). `main` contains the review baseline README. Candidate assurance fixtures ran successfully on GitHub. The hosted required gate detected that the base does not yet contain independently reviewed assurance code. [Bootstrap run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46043199862)

## SDK consumer evidence

- Node 24.12.0 and headless Chrome 158.0.8127.37 loaded the installed WASM tarball with SHA-256 `775fe9ec641253e4f649f7b5073d438ace644d2bef76dfb4a667b0b092dc49ad`. Chrome passed the NIST vector, streaming comparison against Web Crypto, independent states, and error and lifecycle checks.
- PyO3 0.23.5, Rust 1.92.0 and CPython 3.13.14 produced a Windows x64 wheel and source distribution. Both passed clean offline consumer tests. The source archive built with vendored dependencies in a fresh Cargo cache. [Python package and test commands](../../sdk/python/README.md)
- The Windows `.NET 10.0.404` NuGet package restored from an empty local feed with the ABC package as its sole entry. The external process loaded the `win-x64` DLL and passed the NIST vector, streaming and lifecycle checks. [NuGet package recipe](../../sdk/dotnet/README.md)
- Wasmtime 50.0.3 executed the `wasm32-wasip2` SHA-256 command with no filesystem preopens. Eight vectors passed, including empty input, NIST `abc`, padding boundaries and multiple reads. [WASI package recipe](../../sdk/wasi/README.md)
- Rust 1.92.0 cross-compiled `abc-sha256` for `thumbv7em-none-eabi`. The library is compile-only evidence for a no-OS Cortex-M target. Firmware linking, peripheral integrations, target execution and entropy assumptions have separate scope. [Rust target description](https://doc.rust-lang.org/rustc/platform-support/thumbv7em-none-eabi.html)

## Formal evidence

Lean 4.31.0 checked the independent SHA-256 model, abstract streaming laws, and SHA3-256 encoding properties. Charon emitted LLBC for the bounded probe and portable Rust SHA-256. Checked refinement of the exact Rust SHA-256 implementation remains open. [Formal evidence](formal-and-fuzz.md) · [Linux Advisory run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46043199955)

## Upstream and research profiles

The exact pinned CPython source closure for HACL* SHA-256 built in the original C, and 34 one-shot and streaming comparisons passed. The local advisory query, source catalog import, checkpoint replay, ChaCha20-Poly1305 and Ed25519 research profiles each have bounded, independent evidence. Secret-bearing production release claims require their own correctness, leakage and review results. [Original C pilot](abc-036-upstream-route.md) · [Research profile scope](../../runtime/research-profiles/README.md)
