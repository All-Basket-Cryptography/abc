# Swift PBKDF2-HMAC-SHA-256

`AbcPbkdf2Sha256Swift.Pbkdf2Sha256.derive` uses the native Swift HMAC package.
The iteration count and output length must both be positive. The
implementation precomputes the keyed HMAC state once for all blocks and
checks the RFC block-index and HMAC input limits before output allocation.
[RFC 8018 § 5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2)

Use Xcode 16.4 with Apple Swift 6.1.2 on macOS 15.

```sh
DEVELOPER_DIR=/Applications/Xcode_16.4.app/Contents/Developer swift test \
  --package-path src/crypto/kdf/pbkdf2-hmac-sha256/impl/swift/AbcPbkdf2Sha256Swift \
  --scratch-path .abc/swift-pbkdf2-tests --configuration release -Xswiftc -warnings-as-errors
```

The test target checks both PBKDF2 vectors from RFC 7914 and compares
boundary cases against an independent reference using CryptoKit HMAC.
Source refinement and compiled-target leakage assurance remain open.
[RFC 7914 § 11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)
