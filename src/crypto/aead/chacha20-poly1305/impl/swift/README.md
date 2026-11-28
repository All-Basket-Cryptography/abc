# ChaCha20-Poly1305 in Swift

`AbcChaCha20Poly1305Swift` uses the first-party Swift ChaCha20 and
Poly1305 packages. `seal` returns ciphertext and a detached 16-byte
tag. `open` returns verified plaintext or nil. `openInto` writes the
plaintext prefix after verifying the tag and preserves the destination
on authentication failure. Use each 12-byte nonce once per 32-byte key.
[RFC 8439 §§2.6–2.8 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.6)

The standalone SwiftPM consumer compares the RFC answer and 174
bidirectional OpenSSL cases and covers invalid tag, ciphertext, AAD,
and destination cases. The Lean algorithm model covers padding and
counter bounds. Swift implementation refinement and compiled timing
remain open.
[Lean AEAD length model](../../spec/ChaCha20Poly1305Lengths.lean)

Use Swift 6.1.2 on macOS. The harness compiles a separate release
consumer with local SwiftPM dependencies.

```sh
python -B src/crypto/cipher/chacha20/impl/swift/check.py aead
```
