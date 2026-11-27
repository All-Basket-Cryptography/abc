# Native Rust Ed25519

`abc-ed25519` exposes pure RFC 8032 Ed25519 over raw byte arrays.
`public_key` derives a 32-byte public key from a 32-byte seed. `sign` accepts
the same seed and signs the supplied message bytes, returning a 64-byte
signature. `verify_strict` accepts a raw public key, message and signature
and applies Dalek's public-key decoder and strict verification policy.
[RFC 8032 § 5.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1)

This is a `no_std` research SDK built directly on `ed25519-dalek` 2.2.0,
with default features disabled and `zeroize` enabled. The upstream signing
key zeroizes its internal seed on drop. The caller retains ownership of
the supplied seed. The standalone manifest and lock reuse the repository's
pinned upstream provider sources. [Dalek 2.2.0 source](https://docs.rs/crate/ed25519-dalek/2.2.0/source/)

| Upstream crate | Version | Crate archive SHA-256 |
| --- | --- | --- |
| `ed25519-dalek` | `2.2.0` | `70e796c081cee67dc755e1a36a0a172b897fab85fc3f6bc48307991f64e4eca9` |
| `curve25519-dalek` | `4.1.3` | `97fb8b7c4503de7d6ae7b42ab72a5a59857b4c937ec27a3d4539dba95b5ab2be` |
| `ed25519` | `2.2.3` | `115531babc129696a58c64a4fef0a8bf9e9698629fb97e9e40767d235cfbcd53` |
| `sha2` | `0.10.9` | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` |
| `zeroize` | `1.8.2` | `b97154e67e32c85465826e8bcc1c59429aaaf107c1e4a9e53c8d8ccd5eff88d0` |

The Dalek archive records upstream commit `8016d6d9b9cdbaa681f24147e0b9377cc8cef934`
and carries the BSD-3-Clause license. The lock records the full dependency set.
[Pinned upstream tree](https://github.com/dalek-cryptography/curve25519-dalek/tree/8016d6d9b9cdbaa681f24147e0b9377cc8cef934/ed25519-dalek)

## Reproduction

Use Rust 1.92.0 and an existing Cargo cache. The final `--include-ignored`
also runs the interoperability test. Make the OpenSSL CLI available on
`PATH` or select its executable with `ABC_ED25519_OPENSSL`.

```sh
cargo +1.92.0 test --release --locked --offline \
  --manifest-path src/crypto/signature/ed25519/impl/rust/Cargo.toml \
  --target-dir .abc/ed25519-native -- --include-ignored --nocapture
```

The Windows x64 run passed three RFC 8032 known-answer vectors and strict
rejection cases with Rust 1.92.0. OpenSSL 3.5.4 independently agreed on
three public keys and deterministic signatures for messages of 1, 257
and 4,097 bytes, with verification in both directions. The OpenSSL test
encodes its synthetic fixtures with RFC 8410 DER. Exact source refinement
and compiled-target leakage assurance remain open.
[RFC 8032 § 7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1) · [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html)
