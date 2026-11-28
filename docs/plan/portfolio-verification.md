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
| SHA3-256 and SHAKE256 | The Keccak word-row proof shows that the new linear chi indexing agrees with modulo indexing. The squeeze proof covers arbitrary finite read partitions and connects every returned bit to the FIPS bit sponge. [Reader and composition proofs](../../src/crypto/hash/keccak-p1600/spec) · [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202) | The ECMAScript buffer and permutation source correspondence remains open. |
| AES-256-GCM | Eleven Lean statements link the extracted Rust multiplication, block absorption, length field and tag masking to NIST. Their composition agrees with the NIST tag word for all admitted AAD and ciphertext in the padded transcript model. The two changed arithmetic models are rejected. [Source replay](../../tools/verification/aes256-gcm) · [GCM composition](../../src/crypto/aead/aes256-gcm/spec) · [SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D) | Rust slice traversal, padding assembly and byte conversion still use the reviewed model. The concrete AES provider, full seal/open source refinement and compiled leakage remain open. |
| HMAC-SHA-256 | Lean proves the prepared inner and outer prefix state model preserves RFC 2104 outputs on arbitrary admissible chunk partitions and preserves the context after a rejected update. The one-shot function and reusable contexts share the pad normalization and tag logic in both JavaScript and TypeScript. [Prepared-state proof](../../src/crypto/mac/hmac-sha256/spec/HmacPrepared.lean) · [RFC 2104 § 4](https://www.rfc-editor.org/rfc/rfc2104.html#section-4) | The proof uses the byte-level SHA-256 state model. ECMAScript source refinement, JIT leakage and key-state erasure remain open. |
| Poly1305 | Fifteen source-derived Lean statements cover radix-26 parsing, 16-byte decoding, the low key-half clamp, full and already-marked partial block recurrence, and final carry normalization. The production release suites and 2,126 oracle cases passed. [Rust proofs and replay](../../tools/verification/poly1305) · [RFC 8439 § 2.5](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5) | Public initialization, chunk assembly, insertion and zeroing of the partial marker, tag final reduction and output, and compiled leakage remain open. |
| Common ECMAScript input boundary | Three Lean statements prove admission and exact byte footprint of fixed and tracking views in the ECMAScript slot model. The updated intrinsic handlers are exercised through all 20 JavaScript and TypeScript profiles. [Input model and tests](../../src/crypto/inputs) · [ECMAScript typed arrays](https://tc39.es/ecma262/multipage/indexed-collections.html#sec-typedarray-objects) | The model assumes the specified intrinsic behavior and synchronous storage stability. Direct ECMAScript source and runtime correspondence remain open. |
| scrypt | The two ROMix passes agree with the RFC model for admitted power-of-two costs. Lean checks table row indexing and truncation followed by masking. The KDF composition uses explicit Salsa20/8 and PBKDF2 contracts. [ROMix and KDF proof](../../src/crypto/kdf/scrypt/spec) · [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html#section-5) | Source extraction, provider correspondence, erasure and failure paths remain open. |
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

## Runtime evidence

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
