# Pure deterministic ML-DSA-65 in Swift

`AbcMlDsa65Swift` derives a 1,952-byte public key from a 32-byte seed
and returns 3,309-byte signatures. The adapter sets deterministic
FIPS 204 signing explicitly, and accepts up to 255 bytes of binary
context. The provider applies Pure ML-DSA message encoding.
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) ·
[OpenSSL ML-DSA signatures](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/) ·
[RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html)

The isolated consumer checks four pinned ACVP cases and 12 exact
signatures from Go 1.27.4, plus malformed lengths and wrong contexts.
Provider source refinement, compiled timing and runtime key erasure
remain open.
[ACVP provenance](../../spec/acvp-fips204-sample.json)

Use Xcode 16.4 and Swift 6.1.2 on macOS arm64. Select the installed
OpenSSL 3.5.9 `libcrypto` with `PKG_CONFIG_PATH`.
Use Go 1.27.4 for the independent oracle.

```sh
python -B src/crypto/kdf/argon2id/impl/swift/check.py ml-dsa-65
```
