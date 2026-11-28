# AES, RFC 8439, JVM curve and scrypt evidence

[The profile matrix](multi-language-qualification.md) lists the 20 algorithms
and the language, test and proof coverage for each. Each leaf keeps the public
byte interface, toolchain, fixtures and reproduction commands next to its source.
The implementation registry records the exact primary source digest and provider
dependencies.

## Specifications and test inputs

| Profile | Primary material |
| --- | --- |
| AES-256 | FIPS 197 defines the 256-bit key schedule and both block directions. The NIST worked examples provide block vectors. [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) · [SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final) |
| AES-256-GCM | SP 800-38D §§ 6–8 specifies GHASH, counters, authenticated encryption and nonce allocation. The NIST examples cover intermediate states and partial inputs. [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) · [NIST worked GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf) |
| ChaCha20, Poly1305, AEAD | RFC 8439 §§ 2.1–2.8 defines the stream primitive, one-time MAC and authenticated composition. Appendix A records carry and decryption vectors. [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) · [Prior protocol and arithmetic evidence](sponge-and-rfc8439-evidence.md) |
| X25519 | RFC 7748 §§ 5–6 defines scalar clamping, little-endian coordinate decoding, the Montgomery ladder and agreement examples. [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) |
| Ed25519 | RFC 8032 § 5.1 defines point, scalar and signature encoding. Section 7.1 records pure Ed25519 known answers. The ABC profile requires canonical encodings and rejects small-order public and signature points. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) · [ABC profile](../../src/crypto/signature/ed25519) |
| scrypt | RFC 7914 §§ 2–6 defines Salsa20/8, BlockMix, ROMix and PBKDF2 orchestration. Sections 8–12 provide component and whole-output test vectors. [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html) |
| BLAKE2b | RFC 7693 §§ 2–3 defines the sequential digest and output parameter. Appendices A and E provide the trace and self-tests. [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html) · [BLAKE2 design](https://eprint.iacr.org/2013/322) |

## Verified scope

- The full Rust ChaCha20 block refinement is stated over arbitrary 32-byte
  keys, 12-byte nonces and 32-bit counters. It connects the two active
  extracted entry points to the RFC's exact 64-byte output. The pinned
  runner regenerates the Lean model twice and audits nine theorems.
  Stream iteration, error preservation, AEAD composition and compiled
  leakage remain separate obligations. [Proof and reproduction](../../tools/verification/chacha20/README.md)
- C and C++ AES use hardware AES instructions and check CPU capability
  before calling that path. Java and Kotlin AES and GCM use the JVM's
  SunJCE implementation. C# uses .NET cryptography, and Swift uses
  CommonCrypto and CryptoKit. Their receipts identify the exact tested
  runtime and provider scope. JavaScript, TypeScript and Python contain
  their own AES and GHASH operations. The available AES and GCM Lean
  results cover field arithmetic, tag reduction and lengths.
  Whole-source model correspondence and compiled leakage remain open.
  [AES](../../src/crypto/cipher/aes256) · [GCM](../../src/crypto/aead/aes256-gcm)
- The Java and Kotlin curve SDKs fix the SunEC identity and test with
  separate JAR consumers. X25519 covers low-order rejection and
  coordinate aliases. Ed25519 checks the A and R points in addition to
  checking S and invoking provider verification. Lean checks coordinate
  and cofactor arithmetic in the stated public-data models. The JVM
  provider and SDK source still need complete refinement.
  [X25519 model](../../src/crypto/agreement/x25519/impl/java/X25519JvmEncoding.lean) · [Ed25519 model](../../src/crypto/signature/ed25519/impl/java/Ed25519JvmModel.lean)
- The new scrypt leaves test explicit workspace budgets and use independent
  OpenSSL outputs. Lean covers bounds on multiplication, Integerify,
  table offsets and BlockMix destinations. Full composition and source
  refinement remain open. ROMix includes password-dependent accesses.
  [scrypt proof boundaries](../../src/crypto/kdf/scrypt/spec/README.md)

## Measured workloads

The figures are medians reported by each harness for a 4 KiB AES-256-GCM
seal. Compare implementations within each environment. The managed and
ECMAScript harnesses have different allocation and call overheads.

| Environment | Implementation | Provider reference |
| --- | ---: | ---: |
| Windows x64, i7-12700K, Node 24.12.0, OpenSSL 3.5.4 | JavaScript 3,902.56 µs, TypeScript 3,863.83 µs | Node/OpenSSL 8.19 µs |
| Windows x64, .NET 10.0.15 | C# SDK 0.582 µs | .NET direct 0.612 µs |
| macOS arm64, virtual Apple M1, Swift 6.1.2 | Swift SDK 2.80 µs | CryptoKit direct 2.52 µs |

[Node harness](../../src/crypto/aead/aes256-gcm/impl/javascript/benchmark.mjs) · [C# benchmark](../../src/crypto/aead/aes256-gcm/impl/csharp/README.md) · [macOS benchmark and native checks](https://github.com/All-Basket-Cryptography/abc/actions/runs/46090560774/job/140810220948)

On the Windows i7-12700K, the scrypt C11 harness measured 5.58 ms versus
8.90 ms for its OpenSSL reference. The C++17 harness measured 5.64 ms
versus 9.06 ms. Both used N = 4096, r = 8, p = 1 and a 64-byte result.
[C scrypt benchmark](../../src/crypto/kdf/scrypt/impl/c/README.md) · [C++ scrypt benchmark](../../src/crypto/kdf/scrypt/impl/cpp/README.md)

## Native Swift checks

- [BLAKE2b](https://github.com/All-Basket-Cryptography/abc/actions/runs/46087780875/job/140801321717)
- [ChaCha20, Poly1305 and ChaCha20-Poly1305](https://github.com/All-Basket-Cryptography/abc/actions/runs/46090243303/job/140809218931)
- [AES-256 and AES-256-GCM](https://github.com/All-Basket-Cryptography/abc/actions/runs/46090560774/job/140810220948)
- [scrypt](https://github.com/All-Basket-Cryptography/abc/actions/runs/46090777477/job/140810921302)
