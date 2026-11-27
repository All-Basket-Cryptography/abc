# Native cryptography implementation and qualification plan

This plan identifies 20 initial algorithm profiles and the work needed to make
each available in every selected implementation language. The starting SDK
evidence comes from draft PR #1 at `85d2d4dd1ebc3e782ed23f16590599a7a539c419`.
New native-language work is recorded below as it is verified. Each cell advances
on evidence from its own implementation, toolchain, and target. [Baseline revision](https://github.com/All-Basket-Cryptography/abc/tree/85d2d4dd1ebc3e782ed23f16590599a7a539c419) · [Master plan](abc/ABC-MASTER-PLAN.zh-Hant.md)

The SHA-3, BLAKE2b and RFC 8439 changes have a separate index of specifications,
papers, verified statements and measured workloads.
[Recent qualification evidence](sponge-and-rfc8439-evidence.md)

## Languages and targets

The initial language set is Rust, C, C++, Go, Java, JavaScript, TypeScript,
Python, Swift, Kotlin, and C#. This maps the existing and extended SDK scope to
11 source languages and 220 algorithm–language cells before adding targets.
WASI, browser WASM, and embedded are build or deployment targets. Add them to
the per-language target record where the toolchain and API support them.

A native-language cell requires the algorithm body in that language and an
independently installable consumer. A pinned upstream implementation in the
same language can qualify if its exact source, transitive dependencies, and
proof scope are available for review. An FFI or WASM client is recorded as
binding evidence for its provider. JavaScript and TypeScript each need their
own maintained algorithm body to qualify two cells. Compiler-emitted
JavaScript is an artifact of its TypeScript implementation.

| Language | Starting evidence and first target |
| --- | --- |
| Rust | Portable SHA-256, SHA3-256, HMAC, and HKDF cores. Native Windows x64 tests and independent SHA-256 crate consumer. Pinned Linux x64 extraction and Lean refinement for SHA-256, HMAC, and HKDF. |
| C | The existing Windows x64 static and shared SDK uses the Rust C ABI. A separate native C SHA-256 API uses pinned HACL* C from CPython. On Windows x64, Clang 21.1.8 passed three known-answer vectors, 154 OpenSSL one-shot comparisons, 950 streaming snapshots, and error-state preservation and overlap tests. Lean checked four supporting mathematical length and chunking lemmas. Original C source refinement and standalone package qualification remain open. [Native C implementation](../../src/crypto/hash/sha256/impl/c) |
| C++ | The independent C++17 SHA-256 core passed Windows x64 KAT, OpenSSL comparisons, split traces and UBSan. Source refinement remains open. [C++ evidence](../../src/crypto/hash/sha256/impl/cpp) |
| Go | The existing Windows amd64 SDK consumer loads the C ABI DLL. A separate Go SHA-256 implementation passed with Go 1.24.9 and `CGO_ENABLED=0` on Windows amd64 and 386. The amd64 suite reached 98.4% statement coverage and passed 10,000 differential fuzz cases. Independent package consumption, checked source refinement, and performance qualification remain open. [Native Go evidence](../../src/crypto/hash/sha256/impl/go/README.md) |
| Java | The existing JNI SDK uses the Rust C ABI. The separate pure Java SHA-256 JAR passed on Windows amd64 and JDK 17, including 154 one-shot comparisons and 1,042 streaming snapshots. JVM source-to-specification refinement remains open. [Java evidence](../../src/crypto/hash/sha256/impl/java) |
| JavaScript | The independent JavaScript SHA-256 core uses a rolling message schedule. Node known-answer, streaming, differential and ownership checks passed. Browser and source refinement are open. [JavaScript evidence](../../src/crypto/hash/sha256/impl/javascript) |
| TypeScript | The independent TypeScript SHA-256 core uses an expanded schedule and rotating working-register indices. Strict typing and Node runtime, streaming and ownership checks passed. Source-to-generated-code correspondence is open. [TypeScript evidence](../../src/crypto/hash/sha256/impl/typescript) |
| Python | Independent pure-Python SHA-256 passed known answers and differential streaming tests with CPython. Source refinement is open. [Python evidence](../../src/crypto/hash/sha256/impl/python) |
| Swift | Independent pure Swift SHA-256 has a release-mode CryptoKit comparison and source digest receipt in the macOS workflow. Consult the workflow for runtime status. iOS and source refinement are open. [Swift evidence](../../src/crypto/hash/sha256/impl/swift) |
| Kotlin | Independent Kotlin SHA-256 passed known-answer, differential and streaming tests from a separate JAR consumer on JDK 17. JVM source correspondence and Android/ART qualification are open. [Kotlin evidence](../../src/crypto/hash/sha256/impl/kotlin) |
| C# | The independent managed SHA-256 package passed a separate Windows x64 .NET 10 consumer installed from an offline NuGet feed. CIL/runtime correspondence is open. [C# evidence](../../src/crypto/hash/sha256/impl/csharp) |

[SDK qualification](../status/pr-1-qualification.md) · [Original C pilot](../status/abc-036-upstream-route.md) · [Linux proof run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46058290574/job/140706065190)

## Algorithm profiles

Use the exact editions and vector sections below. At import, record the
publisher, document edition, applicable verified errata, upstream commit or
publication identifier, vector filenames, byte digests, and rights. The NIST
sample vectors support engineering conformance tests. Certification is a
separate process. For independently sourced differential tests, record each
oracle's implementation and dependency lineage. Wrappers of the same provider
can corroborate interoperability. [CAVP vector scope](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing)

| # | Profile and type | Primary specification and conformance inputs | Formal target and limits | Current evidence |
| --- | --- | --- | --- | --- |
| 1 | SHA-256, byte-oriented hash | August 2015 FIPS 180-4 §§ 5–6 and the byte-oriented SHAVS vectors. [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) · [SHAVS vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) | Prove the schedule, compression, padding, one-shot and finite update traces, and unchanged state upon rejection. Length domain `8 * length < 2^64`. | Independent source is present for all 11 listed languages. Rust has checked exact API refinement. The individual language rows identify scope, tests and proof gaps. The C adapter has independently checked length and chunking lemmas. |
| 2 | SHA-512, byte-oriented hash | August 2015 FIPS 180-4 § 6.4 and SHA-512 SHAVS byte vectors. [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) · [SHAVS vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) | Prove 64-bit word operations, 128-bit length encoding, streaming, and rejection above the declared per-target cap within the standard's `2^128`-bit domain. Supports Ed25519. | Independent source in all 11 languages with known-answer, differential and streaming suites. Swift 6.1.2 passed on macOS arm64. Lean checks the word schedule, split-word rotations/shift and carry, and length bounds. Exact full source refinement remains open. [SHA-512 evidence](../../src/crypto/hash/sha512/spec) |
| 3 | SHA3-256, byte-oriented hash | August 2015 FIPS 202 and SHA3-256 SHA3VS byte vectors. [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) · [SHA3VS vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) | Prove Keccak-f[1600] rounds, SHA-3 suffix, absorb/squeeze, 32-byte output, and arbitrary chunk traces. Exercise lengths 135, 136 and 137 bytes. | Independent implementations in all 11 languages pass fixed-output conformance vectors and provider comparisons. Lean checks the Keccak permutation, split-word rotations and sponge bit model. Exact source refinement remains open. [Keccak model](../../src/crypto/hash/keccak-p1600/spec) |
| 4 | SHAKE256, byte-oriented extendable-output function | August 2015 FIPS 202 and SHAKE256 SHA3VS byte-output vectors. [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) · [SHAKE vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) | Separate SHAKE suffix, absorb/finalize/squeeze transitions, and equivalence of split reads to one read. Exercise rates and output caps. | Independent implementations in all 11 languages pass split input and split output comparisons. Lean checks the Keccak permutation, split-word rotations and sponge model across finite output blocks. Exact source refinement remains open. [Keccak model](../../src/crypto/hash/keccak-p1600/spec) |
| 5 | BLAKE2b, unkeyed sequential hash with 1–64 output bytes | RFC 7693, Appendix A trace, Appendix C C reference, and Appendix E self-tests. [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html) | Prove parameter block, counter, last block flag, output-size binding, and streaming refinement. Exercise empty, exact block and multiblock inputs. | Independent implementations in 9 languages pass RFC vectors and provider comparisons. New implementations check all 64 digest sizes and incremental snapshots. Lean checks final-block buffer arithmetic. Full source refinement remains open. [BLAKE2b evidence](../../src/crypto/hash/blake2b) |
| 6 | HMAC-SHA-256, full 32-byte MAC | RFC 2104 § 2 and RFC 4231 HMAC-SHA-256 cases. [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html#section-2) · [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html#section-4) | Prove key normalization at 64 bytes, inner/outer hashes, tag, and recoverable update rejection. Reserve 64 bytes of the inner SHA-256 domain. A verification API would also need tag comparison evidence. | Independent Rust, Go, C, C++, C#, Java, Python, JavaScript, TypeScript, Kotlin, and Swift sources. Rust functional refinement remains checked. Native runtime evidence and scope are recorded in each leaf. [Native implementations](../../src/crypto/mac/hmac-sha256/impl) |
| 7 | HKDF-SHA-256, extract-and-expand KDF | RFC 5869 §§ 2–3 and Appendix A.1–A.3. [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#section-2) | Prove extract, empty salt behavior, expand chaining, truncation, 255-block limit, and output ownership and errors. | Independent cores in all 11 languages. Native tests cover RFC vectors, output bounds and 255th-block behavior. Runtime evidence is scoped per leaf. Exact Rust extract/expand/derive refinement remains checked. [Native implementations](../../src/crypto/kdf/hkdf-sha256/impl) |
| 8 | PBKDF2-HMAC-SHA-256, password KDF | RFC 8018 § 5.2 and HMAC-SHA-256 PRF definition. RFC 7914 § 11 examples. [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2) · [RFC 7914 vectors](https://www.rfc-editor.org/rfc/rfc7914.html#section-11) | Prove block indices, PRF iteration and XOR accumulation, admissible positive iteration count and output length, overflow-safe work caps, and error behavior. | Independent cores in all 11 languages. Portable Rust includes checked normalization equivalence and accumulator/index lemmas. Native tests cover standard vectors, validation and independent differential inputs. Exact implementation refinement remains open. [Native implementations](../../src/crypto/kdf/pbkdf2-hmac-sha256/impl) |
| 9 | scrypt, memory-hard password KDF | RFC 7914 §§ 2–6 and component/full vectors in §§ 8–12. [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html) | Prove Salsa20/8, BlockMix, ROMix, PBKDF2 composition, legal parameters, and representable memory/work bounds. | Independent Rust, Go and Python cores pass RFC known answers and OpenSSL provider comparisons. Lean checks the even/odd BlockMix permutation, a power-of-two Integerify mask and ROMix table bounds. Full source refinement and deployment qualification remain open. [scrypt evidence](../../src/crypto/kdf/scrypt/spec) |
| 10 | Argon2id v1.3, memory-hard password KDF | RFC 9106 § 3 and § 5.3 Argon2id vector with secret and associated data. [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3) | Prove variable-length BLAKE2b expansion, indexing, slice/lane scheduling, reductions, and allocation bounds. Treat parameter guidance and encoded password strings as separate API scope. | Independent Rust and Go cores match RFC 9106 H0, per-pass checkpoint words and the final tag with secret and associated data. Both pass 110 OpenSSL cases. Lean checks workspace rounding and lane, reference and flat index bounds. Exact source refinement remains open. [Go results](../../src/crypto/kdf/argon2id/impl/go) |
| 11 | AES-256 encrypt/decrypt, 128-bit block primitive | May 2023 FIPS 197 update and AES-256 encrypt/decrypt KATs. [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) · [AESAVS vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers) | Prove key expansion and forward/inverse rounds. Provide the block primitive to reviewed modes. Hardware and portable backends each need correspondence and leakage evidence. | Table-free Rust and Go cores pass NIST known answers and independent comparisons. Lean checks byte substitution and field-squaring models. Exact source refinement and portable performance qualification remain open. [AES-256 evidence](../../src/crypto/cipher/aes256/spec) · [Go results](../../src/crypto/cipher/aes256/impl/go) |
| 12 | AES-256-GCM, AEAD with 96-bit nonce and 128-bit tag | November 2007 SP 800-38D and applicable AES-256 GCMVS vectors. [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) · [GCMVS vectors](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes) | Prove counter limits, GHASH, associated-data encoding, seal/open, and no plaintext output on authentication failure. Record unique-nonce assumption or verified nonce allocation policy. | Rust and Go cores pass NIST answers, differential tests and rejected-authentication preservation. The separately locked RustCrypto backend passes the same profile, with a 2.160 µs 4 KiB median on the measured x64 host. Lean checks tag reduction and counter bounds. Full source and target leakage refinement remain open. [Accelerated Rust results](../../src/crypto/aead/aes256-gcm/impl/rust/accelerated) · [Go results](../../src/crypto/aead/aes256-gcm/impl/go) |
| 13 | ChaCha20, IETF 96-bit-nonce stream primitive | RFC 8439 block and cipher vectors in §§ 2.3.2 and 2.4.2. [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3.2) | Prove ARX and little-endian encoding, 32-bit counter exhaustion and stream offsets. Keep this primitive separate from the authenticated public API. | Independent implementations in 8 languages pass RFC answers and independent comparisons. Lean checks the extracted Rust 20-round state, counter placement and 16 feedforward additions for every input state and counter. C and C++ have a separately checked translation of the quarter-round arithmetic. Word loading, byte serialization, stream XOR and target leakage remain open. [Rust word refinement](../../tools/verification/chacha20) |
| 14 | Poly1305, full one-time MAC | RFC 8439 § 2.5.2 and Appendix A.3. [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5.2) | Prove clamping, polynomial reduction, padding and output encoding. Record one-time-key scope and cover partial blocks. | Independent implementations in 8 languages pass RFC vectors and independent integer-oracle comparisons. Lean checks the Go limb model across finite traces and proves the JavaScript and TypeScript three-sweep normalization and bounds for 13-bit limbs. Parsing, source extraction and leakage refinements remain open. [Go model](../../src/crypto/mac/poly1305/impl/go) · [13-bit carry model](../../src/crypto/mac/poly1305/spec/Poly1305Radix13.lean) |
| 15 | ChaCha20-Poly1305, IETF AEAD | RFC 8439 § 2.8.2 and Appendix A.5. [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2) | Prove one-time-key derivation, padded AEAD encoding and lengths, counter bounds, successful seal/open, and no plaintext on failure. State the nonce uniqueness policy. | Independent implementations in 7 languages pass RFC vectors and OpenSSL interoperability, including no plaintext output on authentication failure. Lean checks padding and counter bounds. Exact AEAD composition refinement and target leakage remain open. [RFC 8439 suite](../../src/crypto/aead/chacha20-poly1305) |
| 16 | X25519, 32-byte Diffie–Hellman primitive | RFC 7748 §§ 5.2 and 6.1 vectors. [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html#section-5.2) | Prove scalar decoding/clamping, RFC u-coordinate rules, ladder and field implementation. The shared-secret API rejects an all-zero result. Protocol transcript binding needs a separate proof. | Standalone Rust and the pinned native Go provider pass RFC vectors, noncanonical input and low-order checks plus OpenSSL comparisons. Lean checks Rust field reduction, carry bounds and inversion exponents. Complete source refinement remains open. [Rust evidence](../../src/crypto/agreement/x25519/spec) · [Go results](../../src/crypto/agreement/x25519/impl/go) |
| 17 | Ed25519, pure signature profile | RFC 8032 §§ 5.1 and 7.1. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1) | Prove seed/key derivation, point/scalar encoding, signature and verification. Specify strict decoding and small-order-point policies, including their interoperability effects. Ed25519ctx and Ed25519ph have separate scope. | Rust Dalek and Go native profiles pass RFC 8032 and OpenSSL interoperability. The Go profile checks canonical A/R and rejects small-order points by group multiplication. Exact source refinement and runtime qualification remain open. [Rust evidence](../../src/crypto/signature/ed25519/impl/rust) · [Go results](../../src/crypto/signature/ed25519/impl/go) |
| 18 | Deterministic ECDSA P-256 with SHA-256 | FIPS 186-5, SP 800-186 P-256, and RFC 6979 Appendix A.2.5 SHA-256 examples. [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) · [SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final) · [RFC 6979 vectors](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5) | Prove scalar and point range checks, deterministic nonce generation, signing and verification over fixed-width `r` and `s`. DER, recovery, and protocol-specific low-S policy are separate profiles. | RustCrypto and the pinned Go native provider match both RFC 6979 SHA-256 signatures, fixed-width validation and independent OpenSSL interoperability. Source refinement and deployment qualification remain open. [Rust evidence](../../src/crypto/signature/ecdsa-p256-sha256/spec) · [Go results](../../src/crypto/signature/ecdsa-p256-sha256/impl/go) |
| 19 | ML-KEM-768, key encapsulation | August 2024 FIPS 203 with recorded errata disposition. NIST ACVP keyGen and encapDecap vectors at the pinned revision below. [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) · [ACVP keyGen](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-keyGen-FIPS203) · [ACVP encapDecap](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-encapDecap-FIPS203) | Prove sampling and ring/NTT arithmetic, encoding, keyGen, encapsulation and implicit rejection for correctly sized invalid ciphertexts. Qualify randomness and constant-time selection separately. | Pinned AWS-LC 5.5.0 C and Go 1.24.9 native profiles pass selected NIST ACVP data, independent OpenSSL interoperability and implicit rejection. C uses expanded private-key bytes and Go accepts the seed representation. Exact source refinement and deployment qualification remain open. [C evidence](../../src/crypto/agreement/ml-kem-768/spec) · [Go evidence](../../src/crypto/agreement/ml-kem-768/impl/go) |
| 20 | ML-DSA-65, pure deterministic signature profile | August 2024 FIPS 204 with recorded errata disposition. NIST ACVP keyGen, sigGen and sigVer vectors at the pinned revision below. [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) · [ACVP sample vectors](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files) | Prove sampling, ring/NTT arithmetic, encodings, context and rejection checks, keyGen/sign/verify, and the admitted termination behavior of rejection sampling. Hedge and prehash modes are separate profiles. | Pinned AWS-LC 5.5.0 C and Go 1.27.4 native profiles pass selected NIST ACVP cases and exact deterministic OpenSSL interoperability with Pure ML-DSA context. Go imports seeds. Exact source refinement, sampler termination and deployment qualification remain open. [C evidence](../../src/crypto/signature/ml-dsa-65/spec) · [Go evidence](../../src/crypto/signature/ml-dsa-65/impl/go) |

The post-quantum sample revision is NIST ACVP Server `v1.1.0.43` at
`975de31eb83d87039ec88934fdc47d8c312b892d`. Keep the ACVP revision, operation,
parameter set, case IDs, and deterministic test inputs with consumed fixtures.
Test-only randomness must stay outside released APIs. [Pinned ACVP revision](https://github.com/usnistgov/ACVP-Server/commit/975de31eb83d87039ec88934fdc47d8c312b892d)

## Language coverage

The repository contains 128 of 220 implementation combinations across these 20 profiles and 11 languages. 92 combinations remain. Each count includes an implementation leaf, including explicitly recorded pinned native providers. Formal verification and deployment evidence are recorded per profile and per leaf.

| Language | Profiles with implementations |
| --- | ---: |
| Rust | 18 / 20 |
| C | 13 / 20 |
| C++ | 11 / 20 |
| Go | 20 / 20 |
| Java | 10 / 20 |
| JavaScript | 11 / 20 |
| TypeScript | 11 / 20 |
| Python | 12 / 20 |
| Swift | 7 / 20 |
| Kotlin | 7 / 20 |
| C# | 8 / 20 |

SHA-256, SHA-512, SHA3-256, SHAKE256, HMAC-SHA-256, HKDF-SHA-256 and PBKDF2-HMAC-SHA-256 have native execution evidence for all 11 languages. [macOS Swift SHA3-256 and SHAKE256](https://github.com/All-Basket-Cryptography/abc/actions/runs/46083292554)

## Go portfolio

The tests for all 20 Go profiles and the shared Go Keccak module passed on Windows amd64 with Go 1.27.4 and `CGO_ENABLED=0`. [Go 1.27.4 release](https://go.dev/doc/devel/release#go1.27.4)

The PowerShell commands below rerun the leaf suites from the repository
root with Node 24.12 and OpenSSL 3.5.4 available. Set
`ABC_MLDSA_OPENSSL` to the OpenSSL executable if it is outside PATH.
Go verifies module dependencies against their locked checksums.

```powershell
$env:GOTOOLCHAIN = 'go1.27.4'
$env:CGO_ENABLED = '0'
$modules = rg --files src/crypto -g go.mod |
    Where-Object { $_ -match '[/\\]impl[/\\]go[/\\]go\.mod$' }
foreach ($module in $modules) {
    go test -C (Split-Path $module -Parent) -count=1 -tags interop ./...
    if ($LASTEXITCODE -ne 0) { throw "Go suite failed for $module" }
}
node src/crypto/signature/ed25519/impl/go/verify.mjs
if ($LASTEXITCODE -ne 0) { throw 'Ed25519 interoperability failed' }
```

## Delivery order and evidence

1. Start with a native SHA-256 package and the bounded arithmetic proof probe
   in each language. Reuse the mathematical specification and vector corpus.
   Pin the exact compiler, interpreter, or VM and document the bridge from
   original source semantics into the checked model. Cover fixed-width word
   behavior, slices and bounds, failures, and termination. The existing Rust
   Charon/Aeneas and Lean pipeline is the reference for evidence structure.
2. Add SHA-512, SHA3-256, SHAKE256, BLAKE2b, HMAC, and HKDF. In each language,
   reuse proven dependencies through checked function contracts. Run clean
   package consumers and compare results across languages and against the
   pinned tests and independent oracle.
3. Add symmetric primitives and AEAD, then password KDFs, curve operations,
   and standardized lattice schemes. The dependency graph carries impact
   from primitives into constructions. Prove bounds and validation before
   extending an API beyond the qualified parameter and target set.
4. Record for every algorithm a specification and literature inventory,
   original ownership and revision, normative sections, incorporated errata,
   reference vector/oracle lineage and rights, security assumptions, known
   analyses and limitations, plus the claims each artifact actually checks.
   Include the source and object digests, enabled features, target and
   toolchain, theorem and trusted statement, transitive axioms, excluded
   behavior, replay command, and independent review for each proof result.
5. For each target, test malformed input, exhaustion, API state transitions,
   and applicable failure atomicity. Keep source refinement, original-language
   memory/runtime behavior, compiled artifact correspondence, and timing and
   leakage evidence as separately scoped claims. Secret-bearing APIs require
   applicable platform RNG, key lifetime, and failure evidence. On managed or
   JIT targets, characterize the specific runtime and record unresolved
   timing or memory guarantees with the result.
6. Benchmark reviewed builds using pinned toolchain and target, a reproducible
   workload and seed, and repeated independent samples. Capture small-input
   latency, throughput over representative sizes, allocation and memory
   costs, and warm-up and CPU configuration. Compare to the qualified
   baseline on the same machine. Keep the portable implementation as a
   reference when adding SIMD, assembly, or platform backends. Qualify each
   optimized dispatch path with equivalence, failure, leakage, and consumer
   evidence before putting it in a production profile.

Track each cell through implementation, conformance, refinement, target
qualification, and independent release review. The current proof success
covers only the named Rust implementations of SHA-256, HMAC-SHA-256, and
HKDF-SHA-256. The initial 20-by-11 backlog includes the remaining language
implementations and unqualified parts of the existing ones. [Formal and fuzz evidence](../status/formal-and-fuzz.md) · [Assurance policy](../security/trust-and-source-policy.md)
