# Poly1305 in Swift

`AbcPoly1305Swift` exposes a streaming `Poly1305` and the
one-shot `authenticate`. Every message needs a fresh 32-byte key.
The instance takes arrays or array slices and closes when it
returns its 16-byte tag or the caller invokes `close`.
[RFC 8439 §§2.5 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5)

The standalone SwiftPM consumer checks eight RFC cases at every split,
512 expanded-polynomial comparisons and 32 OpenSSL EVP-MAC cases.
The Lean reduction theorem covers the mathematical recurrence. Swift
limb refinement, compiled timing and runtime key erasure remain open.
[Lean reduction model](../../spec/Poly1305Reduction.lean)

Use Swift 6.1.2 on macOS. The harness compiles a separate release
consumer with local SwiftPM dependencies. Select the OpenSSL 3 CLI
with `ABC_OPENSSL` when needed.

```sh
python -B src/crypto/cipher/chacha20/impl/swift/check.py poly1305
```
