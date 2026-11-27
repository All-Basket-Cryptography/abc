# Swift HMAC-SHA-256

`AbcHmacSha256Swift.HmacSha256` uses the independent Swift SHA-256 package for
key normalization and both HMAC passes. `authenticate` returns the full
32-byte tag. A streaming instance accepts full arrays or checked slices,
provides tag snapshots and has value-semantic copies. [RFC 2104 § 2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2)

Use Apple Swift 6.1.2 from Xcode 16.4, macOS 15 and Python 3.11 or newer.

```sh
DEVELOPER_DIR=/Applications/Xcode_16.4.app/Contents/Developer \
  python3 -B src/crypto/mac/hmac-sha256/impl/swift/check.py --output .abc/hmac-sha256-swift-native
```

The test target runs RFC 4231 vectors and uses CryptoKit's HMAC as the
independent oracle for key and message boundaries. It exercises streaming
snapshots, rejected slices and ownership. The hosted workflow records the
suite outcome and both implementation source digests. Source refinement,
compiled-target leakage and key erasure remain open. [RFC 4231 § 4](https://www.rfc-editor.org/rfc/rfc4231.html#section-4)
