# Deterministic P-256 with SHA-256 in Swift

`AbcEcdsaP256Swift` accepts a 32-byte big-endian scalar in `1..<n`
and derives a 65-byte SEC 1 point. `sign` hashes with SHA-256 and selects
OpenSSL's RFC 6979 nonce type. Signature fields are fixed 32-byte
big-endian integers in P1363 `r || s` order. Verification accepts
valid 33-byte compressed and 65-byte uncompressed SEC 1 points.
It accepts both valid S representatives.
[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html) ·
[SEC 1](https://www.secg.org/sec1-v2.pdf) ·
[OpenSSL ECDSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ECDSA/)

The isolated consumer tests the RFC public key and two exact RFC
signatures plus 48 independent CryptoKit checks in both directions.
Complete Swift/provider refinement and compiled timing remain open.

Use Xcode 16.4 and Swift 6.1.2 on macOS arm64. Select the installed
OpenSSL 3.5.9 `libcrypto` with `PKG_CONFIG_PATH`.

```sh
python -B src/crypto/kdf/argon2id/impl/swift/check.py ecdsa-p256-sha256
```
