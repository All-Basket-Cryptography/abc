# Argon2id in Swift

`AbcArgon2idSwift` derives a raw Argon2id v1.3 tag from password,
salt, optional secret and associated data. The API validates the
32-bit limits, the valid work factors, at least eight salt bytes
and at least four tag bytes before calling OpenSSL 3.5 EVP.
The explicit budget covers the requested matrix and output byte
counts. OpenSSL owns the matrix and any provider overhead. This
configuration uses one execution thread for all lanes.
[RFC 9106 §§3–5](https://www.rfc-editor.org/rfc/rfc9106.html#section-3) ·
[OpenSSL EVP_KDF Argon2](https://docs.openssl.org/3.5/man7/EVP_KDF-ARGON2/)

The isolated consumer compares 110 cases with the ABC Go arithmetic,
including the RFC vector with a nonempty secret and associated data,
misaligned memory and the address-batch edge. The Lean model covers
workspace arithmetic. Provider source, allocation details, runtime
key lifetime and compiled behavior remain outside that proof.
[Lean bounds](../../spec/Argon2idBounds.lean)

Use Xcode 16.4 and Swift 6.1.2 on macOS arm64. Select the installed
OpenSSL 3.5.9 `libcrypto` with `PKG_CONFIG_PATH`.
Use Go 1.27.4 for the independent oracle.

```sh
python -B src/crypto/kdf/argon2id/impl/swift/check.py argon2id
```
