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
| SHA-512 | The source-derived byte API agrees with FIPS 180-4 for one-shot input and arbitrary finite x86-64 slice traces. Checked paths cover initialization, accepted byte/block updates, rejection without state changes, final padding, digest serialization and the public one-shot wrapper. Three recompiled Rust controls are rejected. [Source replay](../../tools/verification/sha512/README.md) · [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) | The restricted LLBC translation, standard-library operations and reviewed compression iterator driver are trusted. Compiled leakage and correspondence outside the portable x64 Rust path remain open. |
| ChaCha20 | The extracted public Rust stream API terminates and agrees with the RFC byte model and the ABC exhaustion rule for every typed input. Five new Lean statements check the little-endian word XOR and partial-tail model used by JavaScript and TypeScript, including arithmetic and write bounds. [Rust replay](../../tools/verification/chacha20) · [Word-output model](../../src/crypto/cipher/chacha20/spec/ChaCha20WordOutput.lean) · [RFC 8439 § 2.4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4) | The word-output proof assumes the 32-bit and little-endian runtime primitives. ECMAScript source correspondence and compiled leakage remain open. |
| SHA3-256 and SHAKE256 | The extracted Rust SHA3-256 digest and SHAKE256 byte APIs agree with the FIPS 202 bit sponge. SHAKE256 checks initialization, incremental absorption, finalization, cursor and output for every finite input and read partition, and the public `xof` result. The wrapper replay audits 24 statements and rejects seven recompiled Rust changes. [Source replay](../../tools/verification/keccak) · [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202) | The proofs trust the restricted lowering, x86-64 primitive semantics, and Rust standard-library models. Other languages and compiled leakage retain separate obligations. |
| AES-256-GCM | Thirty-two Lean statements check the extracted Rust GHASH arithmetic, full-block traversal and padded tail, length gates, CTR path, and seal and open orchestration. The CTR check follows counter serialization, partial blocks and byte writes. Open authenticates before writing, and seal authenticates the resulting ciphertext. Ten changed extractions are rejected. [Source replay](../../tools/verification/aes256-gcm) · [SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D) | The concrete AES block implementation and some internal authentication parameter and state wiring retain source obligations. Compiled leakage needs separate target evidence. |
| HMAC-SHA-256 | Lean proves the prepared inner and outer prefix state model preserves RFC 2104 outputs on arbitrary admissible chunk partitions and preserves the context after a rejected update. The one-shot function and reusable contexts share the pad normalization and tag logic in both JavaScript and TypeScript. [Prepared-state proof](../../src/crypto/mac/hmac-sha256/spec/HmacPrepared.lean) · [RFC 2104 § 4](https://www.rfc-editor.org/rfc/rfc2104.html#section-4) | The proof uses the byte-level SHA-256 state model. ECMAScript source refinement, JIT leakage and key-state erasure remain open. |
| Poly1305 | Twenty-nine Lean statements cover the Rust public constructor, streaming update, finalization and one-shot authenticator. The update consumes every full block and preserves the exact short suffix, and the one-shot tag agrees with the RFC integer for arbitrary key and message bytes. The chunk-boundary proof connects successive valid updates. [Source replay](../../tools/verification/poly1305) · [RFC 8439 § 2.5](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5) | The checked model assumes the pinned Aeneas source translation and its Rust library models. Other languages, compiled leakage and host memory handling have separate obligations. |
| Common ECMAScript input boundary | Three Lean statements prove admission and exact byte footprint of fixed and tracking views in the ECMAScript slot model. The updated intrinsic handlers are exercised through all 20 JavaScript and TypeScript profiles. [Input model and tests](../../src/crypto/inputs) · [ECMAScript typed arrays](https://tc39.es/ecma262/multipage/indexed-collections.html#sec-typedarray-objects) | The model assumes the specified intrinsic behavior and synchronous storage stability. Direct ECMAScript source and runtime correspondence remain open. |
| scrypt | The Rust Salsa20/8 core agrees with RFC 7914 on all 512 input bits. The checked word contract instantiates the Salsa20/8 dependency of the alternating ROMix model. Two changed Rust extractions are rejected. [Salsa20/8 proofs and replay](../../src/crypto/kdf/scrypt/spec#rust-salsa208-source-refinement) · [RFC 7914 § 3](https://www.rfc-editor.org/rfc/rfc7914.html#section-3) | Lean uses the model's little-endian packing around the extracted word core. Exact BlockMix, the public `derive` source, PBKDF2 correspondence, workspace erasure and failure paths remain open. |
| ML-KEM-768 | Lean checks integral rounding, decode bounds and recompression of every valid wire value. The sharp cyclic coefficient errors are 104 for 4-bit compression and 2 for 10-bit compression. [Coefficient proofs](../../src/crypto/agreement/ml-kem-768/spec) · [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) | Provider correspondence for coefficient operations and the full key encapsulation refinement remain open. |

## Earlier functional results

| Profile | New verified statement | Remaining implementation work |
| --- | --- | --- |
| SHA-512 | Arbitrary 128-byte block compression, all byte-message digest results, both padding branches, arbitrary finite streaming traces and accepted chunk partitions. Rejected updates preserve the prior state. The runner also rederives IV and round constants and rejects five intentional mutations. [Functional model and audit](../../tools/verification/sha512/README.md) · [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) | This original proof used the reviewed byte-streaming model. The source-derived API verification uses that model as its refinement target. |
| PBKDF2-HMAC-SHA-256 | The complete caller-output model covers the RFC-derived bytes, each output length, all positive iteration counts in the model, and buffer preservation for rejected sizes. Rust now reuses precompressed HMAC key states, with RFC and independent long-password conformance checks. [Lean model and measurements](../../src/crypto/kdf/pbkdf2-hmac-sha256/spec) · [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2) · [RFC 7914 test vectors](https://www.rfc-editor.org/rfc/rfc7914.html#section-11) | Exact source correspondence for the block loop and prepared HMAC context copying remains open. |
| ChaCha20 | The stream model covers every output byte, partial blocks, 32-bit counter exhaustion, involution and input preservation on rejection. It links the bytewise traversal to the checked extracted Rust block. [Lean composition and replay](../../tools/verification/chacha20) · [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4) | The extraction leaves the public Rust iterator combinators opaque. The iterator-to-model connection remains open. |
| ChaCha20-Poly1305 | For the RFC 8439 composition model, the tag comparison consumes all tag bits, the authenticated transcript determines its inputs, valid opening recovers the original plaintext, and rejection preserves caller-owned ciphertext. The Rust-shaped composition theorem states the exact stream and MAC hypotheses. [Lean proof and literature](../../src/crypto/aead/chacha20-poly1305/spec) · [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8) | Exact Rust entry-point extraction and discharge of the provider hypotheses remain open. |

Lean 4.31.0 checks the model statements and their transitive axioms. The
existing SHA-256, HMAC and HKDF source-refinement contracts continue to
apply to their verified entry points and feature configuration. The
full portfolio still requires per-source refinement and compiled
side-channel qualification. [Original exact refinement evidence](../status/pr-1-qualification.md#formal-evidence) · [Linux SHA-256, HMAC and HKDF re-extraction](https://github.com/All-Basket-Cryptography/abc/actions/runs/46096767910/job/140829799978) · [Linux ChaCha20 composition verification](https://github.com/All-Basket-Cryptography/abc/actions/runs/46096767939/job/140829799821)

The updated x86-64 Linux replays passed 24 SHA3/SHAKE statements, five
Salsa20/8 statements, 32 AES-GCM statements and 29 Poly1305 statements.
The runtime record links each source replay to its input digests and
job. [SHAKE256 and Salsa20/8](https://github.com/All-Basket-Cryptography/abc/actions/runs/46109346348/job/140869170148) · [AES-GCM](https://github.com/All-Basket-Cryptography/abc/actions/runs/46109702760/job/140870270112) · [Poly1305](https://github.com/All-Basket-Cryptography/abc/actions/runs/46109346571/job/140869170734)

The Linux replay checked 16 Rust SHA3-256 and SHAKE256 wrapper and reader
theorems, 22 Rust AES-256-GCM theorems, and the scrypt buffer model on
commit `52ce20e`. The SHA3/SHAKE check rejected four re-extracted Rust
mutations. The GCM check rejected six changed extracted operations.
[Linux replay](https://github.com/All-Basket-Cryptography/abc/actions/runs/46107310509/job/140862830326)

A second Linux job checked the 24 extracted Poly1305 theorems, including
public initialization, stale-tail handling and finalization, after two
identical pinned extractions. [Poly1305 Linux replay](https://github.com/All-Basket-Cryptography/abc/actions/runs/46107310473/job/140862830147)

## Construction literature

The [standards matrix](multi-language-qualification.md) lists the governing
documents and test-vector sections for each of the 20 profiles. The following
papers give the security assumptions for the constructions affected by this
round's work. The repository's Lean claims establish the functional results
listed above.

- Bellare's analysis gives HMAC pseudorandomness under assumptions on the
  compression function. [IACR ePrint 2006/043](https://eprint.iacr.org/2006/043.pdf)
- Krawczyk analyzes HKDF in terms of extraction and pseudorandomness
  properties of HMAC. [IACR ePrint 2010/264](https://eprint.iacr.org/2010/264.pdf)
- McGrew and Viega analyze GCM as authenticated encryption with universal
  hashing over a binary field. [IACR ePrint 2004/193](https://eprint.iacr.org/2004/193.pdf)
- Bernstein derives the polynomial authentication bounds behind Poly1305 in
  the Poly1305-AES construction. RFC 8439 specifies the one-time authenticator
  and the ChaCha20-derived key used in this portfolio.
  [Original Poly1305 paper](https://cr.yp.to/mac/poly1305-20041101.pdf) · [RFC 8439 §§ 2.5–2.6](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5)

- Bertoni, Daemen, Peeters and Van Assche describe the sponge construction
  and the random-permutation security model that underlies Keccak.
  [Cryptographic sponge functions](https://keccak.team/sponge_duplex.html)
- Percival motivates scrypt's ROMix with the sequential memory-hard
  cost model. The buffer proof follows RFC 7914's two-pass procedure.
  [Original scrypt paper](https://www.tarsnap.com/scrypt/scrypt.pdf) · [RFC 7914 § 5](https://www.rfc-editor.org/rfc/rfc7914.html#section-5)

## Rust Poly1305 streaming update

The paired Windows x64 runs used Rust 1.92.0 at `-O` with an Intel Core
i7-12700K. Over three runs of eleven alternating batches each, the 64-byte
per-run latency medians went from 41.7–43.1 ns to 35.2–36.2 ns. At one byte,
they went from 31.6–32.0 ns to 32.9–33.4 ns. The recorded sample ranges
overlap at 17 bytes, 65 bytes, 1,025 bytes, and 16 KiB. Release mode passed
six Rust tests and 2,126 comparisons with an independent integer oracle.
[Fixture and reproduction](../../src/crypto/mac/poly1305/spec#rust-streaming-benchmark)

## Native C post-quantum execution

The portfolio's two C post-quantum matrix commands validate reference
fixtures. The companion replay builds the pinned AWS-LC 5.5.0 archive,
links both C leaves to the resulting library, and runs their native
checks against OpenSSL 3.5.4. The recorded Windows x64 run passed eight
ML-KEM ACVP cases, the RFC 9935 key example, four randomized public API
round trips, eight independent interop cases and eight implicit rejection
cases. ML-DSA passed four ACVP and twelve OpenSSL differential cases.
[Native replay and source digests](../../tools/compatibility/portfolio#native-c-post-quantum-supplement) · [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) · [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) · [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935.html)

## ROMix buffer update

The 220-cell compatibility replay combines 207 passing Windows x64 suite
commands and 16 macOS arm64 jobs covering 20 Swift profiles. The Windows
verifier rechecked the source inputs, commands and logs, including a
negative control with a modified log. Node passed 164 ECMAScript test
groups. The C and C++ scrypt runs each passed three RFC known answers,
144 OpenSSL comparisons, workspace and aliasing checks with UBSan enabled.
[Replay record](../status/portfolio-replay.json)

For scrypt on the Windows x64 Intel Core i7-12700K, the paired portable
latencies changed by −2.4% to +1.0% across four languages and three
workloads. Negative figures indicate lower latency. Each entry is the
median microseconds per derive over eleven alternating batches.

| `N`, `r`, `p` | C baseline → current | C++ baseline → current | JavaScript baseline → current | TypeScript baseline → current |
| --- | ---: | ---: | ---: | ---: |
| `16`, `2`, `3` | 46.57 → 46.31 | 31.84 → 31.63 | 137.18 → 133.97 | 184.54 → 184.00 |
| `1024`, `8`, `1` | 1,416.11 → 1,391.44 | 1,384.16 → 1,381.79 | 6,179.69 → 6,137.82 | 6,431.61 → 6,496.92 |
| `512`, `32`, `2` | 5,526.10 → 5,395.94 | 5,319.98 → 5,340.21 | 24,299.35 → 24,155.10 | 25,485.82 → 25,748.20 |

The runs used Clang 21.1.8 for C and C++ and Node 24.12.0 for both
ECMAScript implementations. Direct OpenSSL was faster on all six
ECMAScript workloads. The record includes the distinct OpenSSL versions,
raw samples and source fingerprints. [Paired measurements](../status/scrypt-alternating-benchmark.json) · [Reproduction](../../tools/benchmarks/README.md#paired-scrypt-romix-measurements)

## Runtime evidence

The Poly1305 update replayed 20 profiles per language. The Windows
receipts check the declared commands, source/build fingerprints and
output-log digests for all 200 cells against the final tree. Sixteen
successful macOS arm64 jobs cover the other 20 Swift cells. The updated
ECMAScript suite passed 164 groups. The C++ UBSan harness also checked
Poly1305 against an independent integer reference and
ChaCha20-Poly1305 against OpenSSL.
[Matrix evidence](../status/portfolio-replay.json) · [Verify the saved runner receipts](../../tools/compatibility/portfolio)

The word-output update replayed the 220-cell matrix. The 200 Windows
cells passed 207 commands and all 20 Swift cells passed 16 macOS jobs.
The new repository replay command inventories all 220 cells and records
each chosen cell's source/build inputs and command log hashes. It replayed
the 60 Rust, JavaScript and TypeScript cells in this update. JavaScript and
TypeScript also passed 162 test groups, including all profile input checks,
unaligned and overlapping ChaCha20 views, and resizable word views.
[Replay instructions](../../tools/compatibility/portfolio) · [Current matrix receipt](../status/portfolio-replay.json)

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

The Poly1305 comparison used Node 24.12.0 on the Windows x64 Intel Core
i7-12700K host, with 11 paired samples against `d1b008c`. The 1 KiB medians
below are in microseconds per call. Setup is included. The AEAD test uses
27 bytes of AAD and verifies the exact detached tag and ciphertext.
[Paired samples](../status/poly1305-window-benchmark.json) · [Current ECMAScript timings for all 20 profiles](../status/portfolio-benchmark-poly1305-window.json)

| Public workload | JavaScript baseline → current | TypeScript baseline → current |
| --- | ---: | ---: |
| Poly1305 | 25.36 → 21.42 | 27.40 → 21.44 |
| ChaCha20-Poly1305 seal | 36.51 → 33.47 | 37.40 → 31.53 |

The Node OpenSSL AEAD medians were 3.46–3.61 µs. The C++ `-O2` pairs
against the same baseline measured 507.79 → 483.12 ns and
505.66 → 481.50 ns for 1 KiB. Each C++ trial used nine alternating batches
on Windows x64 with Clang 21.1.8. The data include sample ranges and
additional sizes. [C++ raw summaries](../status/poly1305-cpp-benchmark.json) · [Reproduction](../../tools/benchmarks/README.md#paired-poly1305-measurements)

On Windows x64, Node 24.12.0 and the Intel Core i7-12700K, the 11-sample
comparison against `1d07956` measured the following 1,024-byte medians in
microseconds. The stream operation includes restoring the destination.
AEAD times the full seal with 27 bytes of AAD. Node OpenSSL produced the
same ciphertexts and tags in both languages.
[Paired samples and source digests](../status/chacha20-word-output-benchmark.json) · [All 20 ECMAScript workloads](../status/portfolio-benchmark-word-output.json)

| Public workload | JavaScript baseline → current | TypeScript baseline → current | Direct Node OpenSSL range of medians |
| --- | ---: | ---: | ---: |
| ChaCha20 XOR | 12.03 → 9.22 | 10.93 → 8.48 | 2.57–2.79 |
| ChaCha20-Poly1305 seal | 40.12 → 37.01 | 41.25 → 37.49 | 3.35–3.50 |

The earlier prepared-HMAC replay measured 40 SDK workloads and
19 directly available Node OpenSSL operations. Both language results are
compared before timing. The prepared HMAC update was also measured with
both revisions in the same process, against Node OpenSSL, on Windows x64
with an Intel Core i7-12700K and Node 24.12.0. The table shows medians in
microseconds per operation. Small scrypt differences are sensitive to
run-to-run noise. [All 20 workloads](../status/portfolio-benchmark-prepared-hmac.json) · [Raw paired samples and source digests](../status/hmac-prepared-ecmascript-benchmark.json)

| Public workload | JavaScript `50db178` → current | TypeScript `50db178` → current |
| --- | ---: | ---: |
| SHA-256, 1,024-byte message | 11.89 → 6.04 | 15.70 → 10.97 |
| HMAC, one-shot 32-byte message | 5.04 → 3.83 | 6.76 → 5.73 |
| HMAC, repeated key with reset | 5.16 → 1.84 | 6.56 → 2.58 |
| HKDF-SHA-256, 128-byte output | 27.88 → 14.92 | 34.51 → 21.36 |
| PBKDF2-HMAC-SHA-256, 2,048 iterations | 13,048.08 → 2,989.17 | 11,597.15 → 4,202.00 |
| scrypt, test cost `N=1024`, `r=1`, `p=1` | 847.09 → 820.85 | 898.00 → 862.84 |

Direct Node OpenSSL had lower measured latency on all six workloads.
The native HMAC comparator creates a new context for every message.
[HMAC key state optimization](https://www.rfc-editor.org/rfc/rfc2104.html#section-4) · [HKDF](https://www.rfc-editor.org/rfc/rfc5869.html#section-2) · [PBKDF2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2) · [scrypt](https://www.rfc-editor.org/rfc/rfc7914.html#section-6)

The Rust refactors used for extraction also had paired public-input
checks against `50db178` on the same Windows x64 host with Rust 1.92.0
at optimization level 3. The AES-256-GCM `seal` and valid `open` medians
changed by less than 0.5% across nine alternating batches at both 64
bytes and 64 KiB, with the same AES implementation. Poly1305 one-shot
medians were 40.6 → 40.2 ns at 64 bytes, 402.2 → 401.1 ns at 1 KiB,
and 6,481.4 → 6,317.1 ns at 16 KiB over 11 alternating batches. The
observed ranges overlap. These checks measure throughput on public inputs.

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
