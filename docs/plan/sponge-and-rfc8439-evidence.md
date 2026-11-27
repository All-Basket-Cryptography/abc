# SHA-3, BLAKE2b and RFC 8439 evidence

[The 20-profile matrix](multi-language-qualification.md) records the
implementation and proof status for each profile. Each native module keeps its
API description, dependencies, test entry point and target evidence together.

## Specification and literature

| Profiles | Standards, design and public test inputs |
| --- | --- |
| SHA3-256, SHAKE256 | FIPS 202 §§ 3–6 defines the permutation, sponge, domain suffixes and output. NIST supplies the SHA-3 vector suites. Team Keccak explains the round mapping and publishes the permutation vectors used by the component tests. [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) · [NIST validation vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing) · [Team Keccak summary](https://keccak.team/keccak_specs_summary.html) · [XKCP vectors](https://github.com/XKCP/XKCP/tree/master/tests/TestVectors) |
| BLAKE2b | RFC 7693 §§ 2–3 defines the unkeyed sequential profile, digest parameter, compression, counter and final flag. Appendix A has the trace and Appendix E has self-tests. The design paper motivates the 64-bit BLAKE2b variant. [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html) · [Aumasson et al. (2013)](https://eprint.iacr.org/2013/322) |
| ChaCha20 | RFC 8439 §§ 2.1–2.4 defines the IETF 32-bit counter, 96-bit nonce and 20 rounds. The original ChaCha paper describes the ARX construction and its rotation choices. [RFC 8439 § 2.1](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.1) · [Bernstein, ChaCha (2008)](https://cr.yp.to/chacha/chacha-20080128.pdf) |
| Poly1305 | RFC 8439 § 2.5 defines clamping, the per-block high bit and the one-time authenticator. Appendix A.3 covers final-reduction and carry cases. [RFC 8439 § 2.5 and Appendix A.3](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5) |
| ChaCha20-Poly1305 | RFC 8439 §§ 2.6–2.8 defines key derivation, padding, the two encoded lengths and the authenticated envelope. Appendix A.5 supplies an independent decryption example. [RFC 8439 § 2.8 and Appendix A.5](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8) |

## Verified statements

- The Rust ChaCha20 source extraction checks the four-lane quarter round,
  the column and diagonal round pair, the ten repetitions and the final
  16-word function including counter placement and wrapping feedforward.
  The Linux job runs two independent translations and audits the axioms
  of all four Lean theorems. Key and nonce byte decoding, serialization,
  public stream behavior and machine-code leakage remain open.
  [Reproduction](../../tools/verification/chacha20/README.md) · [Linux run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46084245670/job/140789980127)
- The C and C++ ChaCha20 quarter-round check translates a restricted
  sequence of source arithmetic operations to bitvectors. Full language
  semantics and whole-block refinement remain open.
  [C proof scope](../../src/crypto/cipher/chacha20/impl/c/README.md) · [C++ proof scope](../../src/crypto/cipher/chacha20/impl/cpp/README.md)
- The 13-bit Poly1305 model proves exact normalization and modular
  congruence after three sweeps of ten bounded radix columns, with
  intermediates below the exact integer range of binary64. The connection
  to original JavaScript or TypeScript and tag serialization remains open.
  [Lean carry proof](../../src/crypto/mac/poly1305/spec/Poly1305Radix13.lean)
- The Java arithmetic lemmas cover ChaCha20 counter exhaustion and
  Poly1305 clamping, limb bounds, final selection and tag addition.
  Complete correspondence to Java and its runtime remains open.
  [ChaCha20 lemmas](../../src/crypto/cipher/chacha20/impl/java/ChaCha20StreamingBounds.lean) · [Poly1305 lemmas](../../src/crypto/mac/poly1305/impl/java/Poly1305JavaWords.lean)
- SHA3-256 and SHAKE256 have shared Keccak round and sponge models.
  BLAKE2b has a final-block buffer proof. Exact source contracts for the
  added native hash variants remain open.
  [Keccak model](../../src/crypto/hash/keccak-p1600/spec) · [BLAKE2b buffer model](../../src/crypto/hash/blake2b/spec/Blake2bBuffer.lean)

## Performance evidence

The leaf reports include their own reproducible workloads and environment.
On an i7-12700K running Windows x64, the C11 and C++17 release-mode
ChaCha20-Poly1305 samples measured 6.793 µs and 7.138 µs for a 4 KiB seal.
Node 24.12.0 measured JavaScript at 144.33 µs and TypeScript at 138.63 µs
with 16 AAD bytes, with a 6.46 µs Node/OpenSSL result under that harness.
Cross-harness native and Node results have different call and allocation
overheads. [C run](../../src/crypto/aead/chacha20-poly1305/impl/c/README.md) · [C++ run](../../src/crypto/aead/chacha20-poly1305/impl/cpp/README.md) · [Node benchmark](../../src/crypto/aead/chacha20-poly1305/impl/javascript/benchmark.mjs)

Security review still needs side-channel evidence on the chosen compiler,
runtime and hardware, including key handling and nonce policy. The
performance results apply to the named host, workload and versions.
