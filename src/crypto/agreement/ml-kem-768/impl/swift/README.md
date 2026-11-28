# ML-KEM-768 in Swift

`AbcMlKem768Swift` uses OpenSSL 3.5 for FIPS 203 operations. It accepts
the seed-based private format of 64 bytes `d || z`, derives a
1,184-byte encapsulation key and returns an owned 1,088-byte
ciphertext with a 32-byte shared secret. The encapsulator rejects
noncanonical coefficients. Decapsulation returns the implicit
rejection secret for a correctly sized invalid ciphertext.
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) ·
[OpenSSL ML-KEM](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/) ·
[RFC 9935](https://www.rfc-editor.org/rfc/rfc9935.html)

The isolated consumer checks two pinned NIST key-generation answers,
12 bidirectional Go interoperability cases and exact implicit-rejection
results. Complete source refinement, timing and runtime erasure remain open.
[ACVP provenance](../../spec/acvp.json)

Use Xcode 16.4 and Swift 6.1.2 on macOS arm64. Select the installed
OpenSSL 3.5.9 `libcrypto` with `PKG_CONFIG_PATH`.
Use Go 1.27.4 for the independent oracle.

```sh
python -B src/crypto/kdf/argon2id/impl/swift/check.py ml-kem-768
```
