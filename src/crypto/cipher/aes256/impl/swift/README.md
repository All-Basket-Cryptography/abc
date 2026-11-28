# AES-256 in Swift

`AbcAes256Swift` provides a single-block transform with a 32-byte
key and a 16-byte block. `Aes256.encryptBlock` and `decryptBlock`
delegate to Apple CommonCrypto with no padding. The single-block API
is intended for construction-level use. Use an authenticated mode
such as [AES-256-GCM](../../../../aead/aes256-gcm/impl/swift/)
for messages.
[FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) ·
[NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final) ·
[Apple CommonCryptor](https://github.com/apple-oss-distributions/CommonCrypto/blob/main/include/CommonCryptor.h)

The independent SwiftPM consumer checks two published known answers
and 512 OpenSSL vectors in both directions. The benchmark measures
the wrapper and direct CommonCrypto calls for one 16-byte block.

The Lean model covers AES byte operations. Complete refinement of
CommonCrypto, compiler behavior and target timing remain open.
[AES byte model](../../spec/Aes256Byte.lean)

Run with Xcode 16.4, Swift 6.1.2, and Node/OpenSSL on macOS arm64.

```sh
python -B src/crypto/cipher/aes256/impl/swift/check.py aes256 --benchmark
```
