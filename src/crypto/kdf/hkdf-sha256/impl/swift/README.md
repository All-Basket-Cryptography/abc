# Swift HKDF-SHA-256

`AbcHkdfSha256Swift.HkdfSha256` provides extract, expand and derive. The
implementation uses the native Swift HMAC package. It admits up to 8,160
output bytes and requires at least 32 bytes of PRK for expansion. An omitted
salt uses a 32-byte zero value. [RFC 5869 § 2](https://www.rfc-editor.org/rfc/rfc5869.html#section-2)

Use Xcode 16.4 with Apple Swift 6.1.2 on macOS 15.

```sh
DEVELOPER_DIR=/Applications/Xcode_16.4.app/Contents/Developer swift test \
  --package-path src/crypto/kdf/hkdf-sha256/impl/swift/AbcHkdfSha256Swift \
  --scratch-path .abc/swift-hkdf-tests --configuration release -Xswiftc -warnings-as-errors
```

The test target checks RFC vectors, empty output, rejection and comparisons
against CryptoKit HKDF up to the output limit. Source refinement and
compiled-target leakage assurance remain open.
[macOS arm64 run with two RFC vectors and 60 comparisons](https://github.com/All-Basket-Cryptography/abc/actions/runs/46073888423/job/140756987395)
