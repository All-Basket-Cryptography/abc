# ChaCha20 in Swift

`AbcChaCha20Swift` exposes `ChaCha20.block`, `xor` and `xorInto`
for a 32-byte key, a 12-byte nonce and a 32-bit initial counter.
The API checks capacity and the counter domain before writing. Use
each nonce and counter range once per key.
[RFC 8439 §§2.3–2.4 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3)

The standalone SwiftPM consumer checks two RFC vectors, 144
OpenSSL ciphertexts, the final counter and the destination bounds.
The Lean quarter-round and counter models cover their mathematical
specifications. Correspondence to the Swift core and compiler output
remains open.
[ChaCha20 specification](../../spec/)

Use Swift 6.1.2 on macOS. The harness compiles a separate release
consumer with local SwiftPM dependencies.

```sh
python -B src/crypto/cipher/chacha20/impl/swift/check.py chacha20
```
