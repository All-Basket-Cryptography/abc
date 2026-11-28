# Argon2id, elliptic-curve and post-quantum qualification

The portfolio starts from the 170 implementation cells recorded at
`a67485e0d358ff0163acafcdd0d9396f92651edf`. This update addresses the
remaining entries for six profiles. Each algorithm keeps its SDK entry points
under `src/crypto/<category>/<profile>/impl/<language>`. Individual READMEs
specify the accepted byte formats, errors, dependency versions and reproducers.
The registry hashes the first listed adapter source. Subordinate source and
lockfiles are listed with the adapter where applicable. See the
[20-profile coverage matrix](multi-language-qualification.md).

## Primary literature and conformance material

| Profile | Standards, design literature and inputs |
| --- | --- |
| Argon2id v1.3 | RFC 9106 §§ 3–5 defines initialization, data-dependent and independent indexing, and checkpoints including secret and associated data. The original design paper describes the memory-hardness goals and parameter trade-offs. [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) · [Biryukov, Dinu and Khovratovich, IEEE EuroS&P 2016](https://orbilu.uni.lu/handle/10993/31652) · [Argon2id leaf documentation](../../src/crypto/kdf/argon2id) |
| X25519 | RFC 7748 §§ 5–6 defines decoding, scalar clamping, ladder and all-zero shared-secret handling. Bernstein's original paper explains the curve and field choice. RFC 8410 defines the provider key container. [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) · [Bernstein, PKC 2006](https://iacr.org/archive/pkc2006/39580209/39580209.pdf) · [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html) · [X25519 leaf documentation](../../src/crypto/agreement/x25519) |
| Pure Ed25519 | RFC 8032 §§ 5 and 7 defines byte encodings and known-answer cases. The profile checks canonical points and scalar and rejects small-order A and R. The original paper gives the signature design. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) · [Bernstein et al., CHES 2011](https://ed25519.cr.yp.to/ed25519-20110926.pdf) · [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html) · [Ed25519 leaf documentation](../../src/crypto/signature/ed25519) |
| Deterministic ECDSA P-256 | FIPS 186-5 defines ECDSA and SP 800-186 specifies P-256 parameters. The SDK profile uses the RFC 6979 nonce state machine and the SHA-256 vectors in A.2.5. It preserves S and uses fixed-width big-endian r∥s. [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) · [SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final) · [SEC 1 v2.0](https://www.secg.org/sec1-v2.pdf) · [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html) · [ECDSA leaf documentation](../../src/crypto/signature/ecdsa-p256-sha256) |
| ML-KEM-768 | FIPS 203 defines the standardized KEM, including key canonicality and implicit rejection. The CRYSTALS-Kyber design package gives the historical derivation. The local ACVP fixture records input hashes and source revision. [FIPS 203 and errata](https://csrc.nist.gov/pubs/fips/203/final) · [Avanzi et al., Kyber 3.02](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf) · [ACVP provenance and vectors](../../src/crypto/agreement/ml-kem-768/spec/acvp.json) |
| Pure deterministic ML-DSA-65 | FIPS 204 specifies domain separation, the 255-byte context limit, deterministic signing and verification. The Dilithium paper covers design goals and security assumptions. RFC 9881 specifies provider key containers. Local conformance samples pin the upstream ACVP commit and case IDs. [FIPS 204 and errata](https://csrc.nist.gov/pubs/fips/204/final) · [Ducas et al., Dilithium](https://eprint.iacr.org/2017/633) · [Dilithium 3.1 design package](https://pq-crystals.org/dilithium/resources.shtml) · [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html) · [ACVP provenance and vectors](../../src/crypto/signature/ml-dsa-65/spec/acvp-fips204-sample.json) |

## Provider and runtime evidence

- Java and Kotlin build separate consumer JARs against Bouncy Castle Java 1.87. Per language, Argon2id compares 101 cases with OpenSSL. P-256 checks both exact RFC answers and 50 OpenSSL interoperability cases. ML-KEM adds 7 sampled ACVP checks, 12 two-way OpenSSL exchanges and exact implicit rejection. ML-DSA adds 4 sampled ACVP checks, 16 two-way OpenSSL checks and 12 exact deterministic comparisons. [Provider source](https://github.com/bcgit/bc-java/tree/dd1e61c26066d0793d3f348bf6b4d9b73b701e77) · [Package pin](../../src/crypto/agreement/ml-kem-768/impl/java/bcprov.toml)
- JavaScript and TypeScript each passed six Node 24.12.0 test suites on Windows x64. Noble supplies an independent curve oracle for X25519 and Ed25519. Portable Rust supplies the Argon2id differential oracle. Noble and OpenSSL exercise post-quantum interoperation. [Versions and lock](../../src/crypto/providers/ecmascript/README.md)
- Python passed six CPython suites on Windows x64. The platform lock verifies the cryptography wheel. Its OpenSSL-backed ML-KEM and ML-DSA compare with independently maintained Noble implementations, including exact deterministic signatures under three contexts. [Wheel and library pin](../../src/crypto/providers/python/README.md)
- The two RustCrypto-backed Rust crates passed release-mode ACVP and input boundary suites on Windows x64 with Rust 1.92.0. Cargo locks the dependency closure. [ML-KEM Rust tests](../../src/crypto/agreement/ml-kem-768/impl/rust/tests/conformance.rs) · [ML-DSA Rust tests](../../src/crypto/signature/ml-dsa-65/impl/rust/tests/conformance.rs)
- Swift runs independent SwiftPM consumers on macOS arm64 using CryptoKit and pinned OpenSSL 3.5.9 where recorded. Portable Go and ACVP supply Argon2id and post-quantum oracles. [Curve25519 run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46093224346) · [Argon2id and post-quantum run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46093693090)

## Checked proofs and remaining obligations

Lean 4.31.0 checks 22 shared theorems for the complete fixed-width input
domains of ML-KEM-768 and X25519. The ML-KEM result proves the three-byte
to two-coefficient encoding bijection and proves equivalence of the
full public-key canonicality check and decode/re-encode identity.
The X25519 result proves the high-bit rule, one-subtraction reduction
and the exact alias classes of all 256-bit encodings. JVM leaves also
carry profile model lemmas for arithmetic and encoding bounds.
[Lean sources and exact scope](../../src/crypto/providers/formal/README.md)

The earlier Rust SHA-256, HMAC, HKDF and ChaCha20-block source-refinement
results retain their original theorem statements. The open obligations
for this update are per-language adapter and provider source refinement,
cryptographic security assumptions and reductions, entropy, compiled-code
side-channel behaviour, and deployment qualification for each target.
OpenSSL deterministic ECDSA needs explicit zero-r/s handling when the
underlying API cannot provide the full RFC state transition. The affected
provider and evidence boundary are documented with each implementation.
[Existing refinement evidence](../status/pr-1-qualification.md#formal-evidence)

## Reproducible performance sample

These are per-operation medians in microseconds on Windows x64, Intel
Core i7-12700K, Node 24.12.0, OpenSSL 3.5.4 and Noble curves 2.4.0.
Each route has 100 warmup calls and five alternating samples of 300 calls.
Inputs are fixed and results are checked before timing. SDK call time
includes key import and its public-point policy. Noble call time
includes its strict verification path. Parentheses give sample min–max.

| Fixed workload | ABC OpenSSL-backed SDK | Direct Noble |
| --- | ---: | ---: |
| X25519 shared secret | 65.0 (64.4–70.1) | 798.1 (785.3–823.8) |
| Ed25519 sign, 1,024 bytes | 65.1 (64.2–67.1) | 403.3 (400.5–416.4) |
| Ed25519 verify, 1,024 bytes | 233.2 (230.1–236.2) | 909.1 (899.9–928.0) |

The comparison covers the listed Node workloads, CPU and runtime. Other
providers and workloads require separate measurements. Leakage testing
requires a separate setup. [Benchmark source](../../src/crypto/providers/ecmascript/benchmark.mjs)

```sh
npm ci --ignore-scripts --no-audit --prefix src/crypto/providers/ecmascript
node src/crypto/providers/ecmascript/benchmark.mjs
```
