# ABC progress as of 2026-11-28

The [repository audit](repository-audit.md) records the handoff integrity check, original Git state, and scope. The archived [40-task backlog](../plan/abc/TASKS.json) and [current status overlay](tasks.json) preserve the full scope and prerequisites. Run `python -m tools.abc_cli status` for the combined board or `python -m tools.abc_cli docs build` for the static explorer. [Draft PR #1 qualification](pr-1-qualification.md) records the latest scope and hosted checks.

## Local checks

- The relocated workspace passed 14 Rust tests, including NIST SHA-256 and SHA3-256 vectors, SHA-256 streaming and length boundaries, RFC HMAC and HKDF vectors, and the WASI streaming adapter. Run `cargo +1.92.0 test --manifest-path tools/build/rust/Cargo.toml --workspace --locked --offline`.
- Five registry fixture groups, sixteen Git and planner tests, and four runner tests passed. The local suites verify real Git revision planning, timeout and dependency handling, receipt authentication, cache reuse, and the final gate. The baseline CI CLI passed in a committed scratch repo and rejected a missing worker receipt. [Graph evidence](graph.md)
- The arithmetic probe executed 10,000 native fuzz inputs and rejected a faulty implementation. The extracted SHA-256 revision passed 102,672 differential inputs against RustCrypto with coverage of 227 of 237 LLVM source regions and rejected a deliberately wrong digest. The Windows run used no sanitizer or edge counters. [Formal and fuzz evidence](formal-and-fuzz.md)
- A pinned original-language HACL* compatibility probe used the CPython native `_sha2` backend and an independent OpenSSL comparison. A synthetic upstream drill identified affected and unresolved releases and ran the installed Python compatibility checks. [Original-language probe](abc-036-upstream-route.md) · [Upstream drill](upstream-maintenance-drill.md)
- The local public-input benchmark measured 1 MiB SHA-256 throughput at a median of 334.85 MiB/s. [Benchmark result and environment](abc-039-benchmark.md)

## Packaged research SDKs

`python -m tools.abc_cli conformance --output dist/conformance-v0-1` builds and tests research packages in separate consumer projects. Supply `--browser` with the Chrome executable to qualify the browser target. The Windows Java build uses `ABC_JAVA_HOME` pointing at JDK 17. On this host, invoke the installed Python executable directly because the Windows Store alias is unavailable.

| SDK | Local package and test scope |
| --- | --- |
| Rust | Source crate extraction and clean Cargo consumer, Rust 1.92.0 |
| C | Windows x64 ZIP, static and shared CMake consumers, eight-symbol ABI baseline |
| C++ | Windows x64 ZIP, C++17 CMake consumer using the C ABI |
| Go | Windows amd64 Go 1.24.9 module and DLL, clean offline consumer with `CGO_ENABLED=0` |
| Java | Windows amd64 JNI JAR and POM, Java 17.0.12 consumer with `-Xcheck:jni`. The JVM reported local-reference warnings from its `NetworkInterface.getAll` entropy enumeration. The consumer passed. |
| npm | Installed tarball with WASM and TypeScript declarations, Node 24.12 and Chrome 158 external consumers |
| Python | Windows x64 CPython 3.13 PyO3 wheel and source distribution, separate offline virtual environments |

[Native SDK evidence](native-sdks.md) and the [Node backend decision](../architecture/decisions/node-backend.md) record additional checks. The seven SDKs share the Rust SHA-256 core. This package set establishes the compatibility baseline.

## Remaining acceptance

- M0 has a passing pinned Rust-to-Lean bounded probe. M1 candidate fixtures passed on GitHub. The hosted required gate awaits an independently reviewed Git baseline.
- M2 has checked SHA-256, HMAC-SHA-256 and HKDF-SHA-256 implementation refinements and browser WASM coverage. The three refinements await independent review. The SHA3-256 implementation proof scope remains open. [Formal evidence](formal-and-fuzz.md) · [HMAC and HKDF checks](../../tools/verification/hmac-hkdf/README.md)
- M3 through M5 have local research packages, a Rust/npm research replay path, and initial governance and upstream tooling. Production approval, broader platform evidence, previous-version compatibility, and backlog expansion remain open. The [acceptance review](acceptance.md) records each check.

The Rust and npm research set passed exact-byte replay from clean build directories. Use `python -m tools.abc_cli release prepare --profile research --output dist/research` and `python -m tools.abc_cli release verify --manifest dist/research/release-set.json` to repeat the check. The manifest records the source snapshot and local consumer results. Production eligibility requires a reviewed source revision, independent review, and checked assurance evidence.
