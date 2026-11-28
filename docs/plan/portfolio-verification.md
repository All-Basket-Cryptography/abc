# Portfolio verification and comparative performance

The 20 existing profiles have 220 maintained SDK combinations across
Rust, C, C++, Go, Java, JavaScript, TypeScript, Python, Swift, Kotlin and
C#. The replay combines Windows x64 execution with hosted macOS arm64
Swift execution. Evidence stays tied to the leaf and toolchain that ran.
The portfolio includes original-language cores and identified provider
adapters. See the [standards and SDK matrix](multi-language-qualification.md)
and the [per-language runtime replay](../status/portfolio-replay.json).

## Source checks and new functional models

| Profile | Checked result | Remaining boundary |
| --- | --- | --- |
| SHA-512 | Two Charon extractions of the real Rust compressor produce identical Lean bodies for big-endian loading, schedule indexing, all eight round outputs and feed-forward. Lean composes these bodies with the fixed-array driver model and proves equality to FIPS 180-4 for every 128-byte block and initial state. Recompiling a changed rotation breaks the Lean check. [Source replay](../../tools/verification/sha512/README.md) · [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) | Rust iterator order, the restricted LLBC translator and its primitive semantics remain in the trust boundary. The Rust streaming source bridge, general memory semantics and compiled leakage remain open. |
| ChaCha20 | The extracted public Rust stream API terminates and agrees with the RFC byte model and the ABC exhaustion rule for every typed input. The proof covers returned status, length and every byte, including preservation of the whole caller slice after rejection. [Source refinement and replay](../../tools/verification/chacha20) · [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4) | The claim is scoped to the extracted Rust model and its declared trust base. Compiled leakage and source correspondence for other SDKs remain open. |
| SHA3-256 and SHAKE256 | The Keccak word-row proof shows that the new linear chi indexing agrees with modulo indexing. The squeeze proof covers arbitrary finite read partitions and connects every returned bit to the FIPS bit sponge. [Reader and composition proofs](../../src/crypto/hash/keccak-p1600/spec) · [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202) | The ECMAScript buffer and permutation source correspondence remains open. |
| AES-256-GCM | The 128-round mask-based GHASH model agrees with the published arithmetic. Separate theorems cover padding, length packing, CTR chunking, complete tag equality and rejection. The sealing and opening theorems use an explicit AES block contract, and Lean recomputes the NIST example. [GCM proofs and vectors](../../src/crypto/aead/aes256-gcm/spec) · [SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D) | The source extraction and the actual provider's block contract remain open. |
| scrypt | The two ROMix passes agree with the RFC model for admitted power-of-two costs. Lean checks table row indexing and truncation followed by masking. The KDF composition uses explicit Salsa20/8 and PBKDF2 contracts. [ROMix and KDF proof](../../src/crypto/kdf/scrypt/spec) · [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html#section-5) | Source extraction, provider correspondence, erasure and failure paths remain open. |
| ML-KEM-768 | Lean checks integral rounding, decode bounds and recompression of every valid wire value. The sharp cyclic coefficient errors are 104 for 4-bit compression and 2 for 10-bit compression. [Coefficient proofs](../../src/crypto/agreement/ml-kem-768/spec) · [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) | Provider correspondence for coefficient operations and the full key encapsulation refinement remain open. |

## Earlier functional results

| Profile | New verified statement | Remaining implementation work |
| --- | --- | --- |
| SHA-512 | Arbitrary 128-byte block compression, all byte-message digest results, both padding branches, arbitrary finite streaming traces and accepted chunk partitions. Rejected updates preserve the prior state. The runner also rederives IV and round constants and rejects five intentional mutations. [Functional model and audit](../../tools/verification/sha512/README.md) · [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) | The proof connects a source-anchored functional model to the FIPS reference. A compiler-semantics connection to the Rust program and correspondence for the other targets remain open. |
| PBKDF2-HMAC-SHA-256 | The complete caller-output model covers the RFC-derived bytes, each output length, all positive iteration counts in the model, and buffer preservation for rejected sizes. Rust now reuses precompressed HMAC key states, with RFC and independent long-password conformance checks. [Lean model and measurements](../../src/crypto/kdf/pbkdf2-hmac-sha256/spec) · [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2) · [RFC 7914 test vectors](https://www.rfc-editor.org/rfc/rfc7914.html#section-11) | Exact source correspondence for the block loop and prepared HMAC context copying remains open. |
| ChaCha20 | The stream model covers every output byte, partial blocks, 32-bit counter exhaustion, involution and input preservation on rejection. It links the bytewise traversal to the checked extracted Rust block. [Lean composition and replay](../../tools/verification/chacha20) · [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4) | The extraction leaves the public Rust iterator combinators opaque. The iterator-to-model connection remains open. |
| ChaCha20-Poly1305 | For the RFC 8439 composition model, the tag comparison consumes all tag bits, the authenticated transcript determines its inputs, valid opening recovers the original plaintext, and rejection preserves caller-owned ciphertext. The Rust-shaped composition theorem states the exact stream and MAC hypotheses. [Lean proof and literature](../../src/crypto/aead/chacha20-poly1305/spec) · [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8) | Exact Rust entry-point extraction and discharge of the provider hypotheses remain open. |

Lean 4.31.0 checks the model statements and their transitive axioms. The
existing SHA-256, HMAC and HKDF source-refinement contracts continue to
apply to their verified entry points and feature configuration. The
full portfolio still requires per-source refinement and compiled
side-channel qualification. [Original exact refinement evidence](../status/pr-1-qualification.md#formal-evidence) · [Linux SHA-256, HMAC and HKDF re-extraction](https://github.com/All-Basket-Cryptography/abc/actions/runs/46096767910/job/140829799978) · [Linux ChaCha20 composition verification](https://github.com/All-Basket-Cryptography/abc/actions/runs/46096767939/job/140829799821)

## Runtime evidence

The Windows replay uses the leaf conformance suites in the dependency
graph. The two C post-quantum suites additionally compile ABC against
the pinned AWS-LC 5.5.0 static library. For ML-KEM-768, the replay checks
eight ACVP cases, eight independent OpenSSL cases, RFC 9935 key encoding,
implicit rejection and four randomized round trips. For ML-DSA-65, it
checks four ACVP cases and 12 OpenSSL interoperability cases.
[ML-KEM C build and conformance](../../src/crypto/agreement/ml-kem-768/spec) · [ML-DSA C build and conformance](../../src/crypto/signature/ml-dsa-65/spec)

The C# RFC 8439 consumer check originally failed during Windows MSBuild
restore. The new runner disables build servers and limits each build
to a single MSBuild node. The combined rerun and three independent
concurrent reruns passed. This covers ChaCha20, Poly1305 and the AEAD.
[C# verification tool](../../src/crypto/cipher/chacha20/impl/csharp/check.py)

The ECMAScript update checks each of the 20 JavaScript and 20 TypeScript
profiles with nonzero-offset byte views, caller-defined accessors,
detached buffers and shared buffers. SHA and SHAKE checks exercise state
after rejection, and direct Keccak checks the write range for a word
view. The SHA-256, SHA-512, HMAC, HKDF, PBKDF2 and Keccak paths now reach
the same intrinsic-accessor boundary used by the other profiles. The
qualification suite ran on Windows x64 and Linux x64 using Node 24.12.0.
[Input contract and replay](../../tools/compatibility/ecmascript-views) · [ECMAScript typed arrays](https://tc39.es/ecma262/multipage/indexed-collections.html#sec-typedarray-objects)

Node AES-256-GCM now has separate synchronous OpenSSL-backed JavaScript
and TypeScript entries. The original portable entries remain available
for browser and portable consumers. The accelerated wrappers retain the
detached-tag contract, output ownership and strict byte-view admission.
Their tests exercise NIST outputs, 216 interoperability cases per
language, authentication failure and handling of temporary plaintext.
[JavaScript Node entry](../../src/crypto/aead/aes256-gcm/impl/javascript) · [TypeScript Node entry](../../src/crypto/aead/aes256-gcm/impl/typescript)

## Measured performance

Rust 1.92.0 PBKDF2 release runs on Windows x64 measured a drop from
3.401 ms to 1.916 ms for a 32-byte password, 4,096 iterations and a
32-byte output. The same settings with a 4,096-byte password measured
3.405 ms and 1.916 ms. Each median comes from nine calls on the same
host, with the old path at `aead74f`. [Rust benchmark and reproduction](../../src/crypto/kdf/pbkdf2-hmac-sha256/spec/README.md)

The ECMAScript replay measures all 20 profiles on the same Windows x64
machine with Node 24.12.0 and OpenSSL 3.5.4. It reports both maintained
language implementations and direct OpenSSL for 19 workloads.
Standalone Poly1305 has both language measurements. Each operation
uses a public fixture and validates its result before timing.
The recorded provider may share the backend with an SDK, as with
Argon2id and X25519. The results characterize their selected APIs and
workloads. [Benchmark source](../../tools/benchmarks/portfolio.mjs) · [Measured values](../status/portfolio-benchmark-node24-windows.json)

For AES-256-GCM seal with 1,024 plaintext bytes, 25 AAD bytes and a
detached 16-byte tag, the JavaScript median was 1,023.70 µs with the
portable entry and 4.26 µs with the Node entry. The TypeScript medians
were 1,030.79 µs and 4.22 µs. Direct Node OpenSSL measured 3.97 µs.
The OpenSSL provider supplies the accelerated cipher and tag arithmetic.

The portable ECMAScript Keccak update reuses permutation scratch arrays
and removes modular addressing from the chi row loop. The paired Node
24.12.0 run checks each result against OpenSSL and alternates versions in
the same process. For a 1,024-byte input, these are the median operation
times in microseconds on a Windows x64 Intel Core i7-12700K.

| Profile and output size | JavaScript baseline → current | TypeScript baseline → current |
| --- | ---: | ---: |
| SHA3-256, 32 bytes | 43.06 → 30.51 | 44.54 → 33.26 |
| SHAKE256, 32 bytes | 41.11 → 29.93 | 42.24 → 31.18 |
| SHAKE256, 1,536 bytes | 95.10 → 68.56 | 96.97 → 70.25 |

The recorded table also includes the 64-byte and 16,384-byte inputs and
the measured ranges. [Paired benchmark and source digests](../status/keccak-ecmascript-benchmark.json) · [Reproduction](../../tools/benchmarks/README.md#paired-sha-3-and-shake-measurements)

The indexed Rust ChaCha20 loop makes the complete stream source
extractable. In two paired Windows x64 runs, its 16 KiB median latency
was 3.9% and 5.6% higher than the previous iterator loop. The trials
also record the 64-byte and 1 KiB results and the reproduction command.
[ChaCha20 stream measurements](../../tools/verification/chacha20/README.md#stream-loop-benchmark)

Benchmarks identify performance gaps within a recorded environment.
Deployment-wide performance rankings, constant-time execution and
production assurance need their own evidence.
