# Deterministic ECDSA P-256 with SHA-256

This Rust research API uses RustCrypto `p256` 0.14.0 at upstream commit
`27e62fdf973ef5f1b0a81d4577bec0aa323cde5f`. The standalone workspace locks
the full dependency graph and enables the upstream `ecdsa` feature with
default features disabled. ABC supplies the byte-format API and conformance
checks. RustCrypto supplies the curve arithmetic, SHA-256 and signing.
[Pinned upstream source](https://github.com/RustCrypto/elliptic-curves/tree/27e62fdf973ef5f1b0a81d4577bec0aa323cde5f/p256)

The API takes a caller-supplied private key as a 32-byte big-endian scalar
with `1 ≤ d < n`. Public key derivation emits a 65-byte uncompressed SEC 1
point. Verification accepts compressed or uncompressed SEC 1 points with
prefixes `02`, `03` or `04` and the corresponding exact lengths. It
rejects invalid coordinates, infinity and hybrid encodings. Signatures use
64 bytes in IEEE P1363 format, with the 32-byte big-endian scalars `r` and
`s` concatenated. Verification requires both scalars to be in `1..n` and
accepts either S representative. Signing preserves the RFC 6979 result
without low-S normalization.
[P-256 domain parameters](https://csrc.nist.gov/pubs/sp/800/186/final)

The provider hashes the supplied message with SHA-256 and uses the RFC
6979 deterministic HMAC-DRBG sequence. Unusable nonce or signature
candidates advance that deterministic sequence. Signing uses no random or
alternative algorithm fallback. Key generation and storage are outside
the API. [RFC 6979 §3.2](https://www.rfc-editor.org/rfc/rfc6979.html#section-3.2)

## Reproduce the checks

```sh
cargo +1.92.0 test --locked --offline --manifest-path src/crypto/signature/ecdsa-p256-sha256/impl/rust/Cargo.toml
node src/crypto/signature/ecdsa-p256-sha256/spec/verify.mjs
```

Rust 1.92.0 on Windows x64 matched the two RFC 6979 SHA-256 signatures and
the published P-256 public key. The tests also cover invalid scalars,
public keys, messages and signatures. Node 24.12.0 with OpenSSL 3.5.4
matched 48 public keys, accepted the corresponding Rust signatures, and
generated 48 signatures that Rust verified. The imported signatures
exercise verification independently of the deterministic signing path.
[RFC 6979 Appendix A.2.5](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5)

Exact provider and API refinement, compiled leakage, key erasure, and
FIPS 186-5 validation remain open.
[FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final)
