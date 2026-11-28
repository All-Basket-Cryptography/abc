# X25519 in Swift

`AbcX25519Swift` uses Apple CryptoKit for single-scalar public-key
derivation and agreement. It accepts raw 32-byte RFC 7748 private scalars
and peer coordinates. Before provider agreement it clears the peer's
top bit, subtracts the field modulus once when needed, and rejects
canonical low-order inputs. `sharedSecret` returns nil for low-order
peers or all-zero output. Incorrect input lengths throw. Authenticate
the peer and use an appropriate KDF for session keys.
[RFC 7748 §§5–7](https://www.rfc-editor.org/rfc/rfc7748.html#section-5) ·
[Apple Curve25519.KeyAgreement](https://developer.apple.com/documentation/cryptokit/curve25519/keyagreement)

The offline SwiftPM consumer checks six RFC results, 196 independent
OpenSSL comparisons, 32 scalar-clamp aliases, three peer aliases and 14
low-order encodings. The Lean coordinate model covers the mathematical
normalization rules. Complete Swift refinement, CryptoKit internals and
compiled timing remain open.
[Lean X25519 encoding model](../java/X25519JvmEncoding.lean)

Use Xcode 16.4, Swift 6.1.2 and Node/OpenSSL on macOS arm64.

```sh
python -B src/crypto/agreement/x25519/impl/swift/check.py x25519
```
