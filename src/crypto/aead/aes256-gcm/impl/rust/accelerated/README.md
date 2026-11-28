# Accelerated AES-256-GCM in Rust

This standalone research profile uses the native RustCrypto AES-GCM
provider with the `aes` and `zeroize` features. The API takes a 32-byte
key and a 96-bit nonce and produces a separate 128-bit tag. Use a
distinct nonce for every sealing operation under a key. The payload
and associated-data limits are checked before writes and compared to
the provider's limits during compilation. Opening verifies the tag
before any plaintext write. [NIST SP 800-38D §§5–8](https://csrc.nist.gov/pubs/sp/800/38/d/final)

RustCrypto's AES and POLYVAL crates use runtime architecture
dispatch on supported targets. POLYVAL provides the field
multiplication used by the provider's GHASH implementation. On the
tested Windows x64 binary, the host reported AES, VAES, AVX and
PCLMULQDQ. Disassembly contained `aesenc`, `vaesenc` and
`vpclmulqdq` instructions.
[AES dispatch source](https://github.com/RustCrypto/block-ciphers/blob/c1534361e7549e29a16c3505f45a04c92d26b62a/aes/src/lib.rs) ·
[POLYVAL intrinsics source](https://github.com/RustCrypto/universal-hashes/blob/b69f449b165afe7a0dcfe076a2572098f2f0a17f/polyval/src/backend/intrinsics/x86.rs) ·
[RFC 8452 Appendix A](https://www.rfc-editor.org/rfc/rfc8452.html#appendix-A)

The lockfile records the dependency closure. The core archives
used in the verified build had these identities.

| Crate | Version | Source commit | Archive SHA-256 |
| --- | --- | --- | --- |
| `aes-gcm` | 0.11.1 | `2eff6ccb137850202ad581afb6e947f302ccbbcf` | `7f2b8006a0c83f52b62ba44a97b58bf76fe2f70a329e588f67f89691d93d498f` |
| `aes` | 0.9.3 | `c1534361e7549e29a16c3505f45a04c92d26b62a` | `35f0f96ce78e38c3dc6d8948aa8163d06385be74000f3c7a95bf1eef35d3ea32` |
| `ghash` | 0.6.0 | `2ec214089615c06e19560cd1222366f5d7c79163` | `2eecf2d5dc9b66b732b97707a0210906b1d30523eb773193ab777c0c84b3e8d5` |
| `polyval` | 0.7.3 | `b69f449b165afe7a0dcfe076a2572098f2f0a17f` | `f0fa31d631f2b2cb2a544d0aa321ce847a94764d701ca2becc411138b93d49cd` |

[Pinned AES-GCM provider](https://github.com/RustCrypto/AEADs/blob/2eff6ccb137850202ad581afb6e947f302ccbbcf/aes-gcm/src/lib.rs)

## Validation

Rust 1.92.0 on Windows x64 passed two NIST known answers, distinct
rejection cases with retained ciphertext and 174 bidirectional
comparisons with Node 24.12 and OpenSSL 3.5.4. The `no_std` library also
passed compile checks for `thumbv7em-none-eabi`, `wasm32-wasip2` and
`aarch64-linux-android`. Those compile checks provide build evidence for
the target. Complete source refinement, compiled leakage and
end-to-end key erasure require target-specific evidence.
[NIST GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)

## Measurement

The benchmark runs both profiles in one release executable with
Rust 1.92.0 on Windows x64 and an Intel Core i7-12700K. Five batches of
128 in-place sealing calls use 16 bytes of associated data and a
distinct nonce for each call. Both timings include per-message
key setup.

| Payload | ABC portable Rust | RustCrypto-backed Rust |
| --- | ---: | ---: |
| 64 bytes | 70.504 µs | 0.257 µs |
| 4 KiB | 2.963 ms | 2.160 µs |

```sh
cargo +1.92.0 test --manifest-path src/crypto/aead/aes256-gcm/impl/rust/accelerated/Cargo.toml --release --locked --offline -- --nocapture
cargo +1.92.0 run --manifest-path src/crypto/aead/aes256-gcm/impl/rust/accelerated/Cargo.toml --release --locked --offline --example aes256gcm_accelerated_bench
```

The offline commands expect the pinned crate archives in Cargo's
cache. The independent provider comparison uses a Node executable
on the path. The NIST and validation cases run with Rust alone.
