# ABC progress as of 2026-11-28

The [repository audit](repository-audit.md) records the handoff integrity check, original Git state, and scope. The archived [40-task backlog](../plan/abc/TASKS.json) and [current status overlay](tasks.json) preserve the full scope and prerequisites. Run `python abc.py status` for the combined board or `python abc.py docs build` for the static explorer.

## Local checks

- `cargo +1.92.0 test --workspace --locked --offline` passed 13 tests, including NIST SHA-256 and SHA3-256 vectors, SHA-256 streaming and length boundaries, and RFC HMAC and HKDF vectors. `cargo +1.92.0 fmt --all -- --check` and `cargo +1.92.0 clippy --workspace --all-targets --locked --offline -- -D warnings` also passed.
- Five registry fixture groups, sixteen Git and planner tests, and four runner tests passed. The local suites verify real Git revision planning, timeout and dependency handling, receipt authentication, cache reuse, and the final gate. The baseline CI CLI passed in a committed scratch repo and rejected a missing worker receipt. [Graph evidence](graph.md)
- The arithmetic probe executed 10,000 native fuzz inputs and rejected a faulty implementation. SHA-256 differential fuzzing executed 124,052 inputs against RustCrypto, covered 195 of 206 LLVM source regions, and rejected a deliberately wrong digest. The measured Windows run used no sanitizer or edge counters. [Formal and fuzz evidence](formal-and-fuzz.md)
- A pinned original-language HACL* compatibility probe used the CPython native `_sha2` backend and an independent OpenSSL comparison. A synthetic upstream drill identified affected and unresolved releases and ran the installed Python compatibility checks. [Original-language probe](abc-036-upstream-route.md) · [Upstream drill](upstream-maintenance-drill.md)
- The local public-input benchmark measured 1 MiB SHA-256 throughput at a median of 334.85 MiB/s. [Benchmark result and environment](abc-039-benchmark.md)

## Packaged research SDKs

`python abc.py conformance --output dist/conformance-verified` built and tested research packages in separate consumer projects. See `dist/conformance-verified/conformance.json` for hashes and results. The Windows Java build uses `ABC_JAVA_HOME` pointing at JDK 17. On this host, invoke the installed Python executable directly because the Windows Store alias is unavailable.

| SDK | Local package and test scope |
| --- | --- |
| Rust | Source crate extraction and clean Cargo consumer, Rust 1.92.0 |
| C | Windows x64 ZIP, static and shared CMake consumers, eight-symbol ABI baseline |
| C++ | Windows x64 ZIP, C++17 CMake consumer using the C ABI |
| Go | Windows amd64 Go 1.24.9 module and DLL, clean offline consumer with `CGO_ENABLED=0` |
| Java | Windows amd64 JNI JAR and POM, Java 17.0.12 consumer with `-Xcheck:jni`. The JVM reported local-reference warnings from its `NetworkInterface.getAll` entropy enumeration. The consumer passed. |
| npm | Installed tarball with WASM and TypeScript declarations, Node 24.12 external consumer. Managed Chrome crashed during startup and the browser connector timed out. |
| Python | Windows x64 CPython 3.13 wheel and sdist, separate offline virtual environments. The binding uses `ctypes` over the C ABI. |

[Native SDK evidence](native-sdks.md) and the [Node backend decision](../decisions/node-backend.md) record additional checks. The seven SDKs share the Rust SHA-256 core. This package set establishes the compatibility baseline.

## Remaining acceptance

- M0 and M1 await a compatible Rust → Charon → Aeneas → Lean run and a hosted workflow run using a reviewed Git baseline. The configured public origin has no source revision to review.
- M2 still requires Lean specification checking and full implementation refinement. HMAC/HKDF and SHA3-256 have working tests and separate pending proof scopes. Browser WASM conformance is open.
- M3 through M5 have local research packages, a Rust/npm research replay path, and initial governance and upstream tooling. Production approval, broader platform evidence, previous-version compatibility, and backlog expansion remain open. The [acceptance review](acceptance.md) records each check.

The Rust and npm research set passed exact-byte replay from clean build directories. `python abc.py release prepare --profile research --output dist/research-current` and `python abc.py release verify --manifest dist/research-current/release-set.json` reproduce the check. The manifest records the source snapshot and local consumer results. Production eligibility requires a reviewed source revision, independent review, and checked assurance evidence.
