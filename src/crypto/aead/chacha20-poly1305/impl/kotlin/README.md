# ChaCha20-Poly1305 in Kotlin

`ChaCha20Poly1305.seal` returns a ciphertext and 16-byte detached tag.
`open` returns verified plaintext or null, and `openInto` updates a
destination only on success. Opening verifies and decrypts the same
ciphertext copy. Give each call stable inputs and exclusive access to
its output. Use a new 12-byte nonce for each encryption under the same
32-byte key.
[RFC 8439 §§2.6–2.8 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.6)

The separately compiled consumer checks the RFC vector, 174 bidirectional
OpenSSL cases, every modified tag byte, modified ciphertext and AAD,
and rejection with a shared input and output array. The Lean length
model covers padding and counter bounds. JVM runtime timing, key
erasure and Kotlin source refinement remain open.
[Lean AEAD length model](../../spec/ChaCha20Poly1305Lengths.lean)

Select the offline Kotlin JVM 2.1.21 distribution with
`ABC_KOTLIN_HOME` and JDK 17 with `ABC_JAVA_HOME` or the path.
Use `--output` to keep the independently checked JARs.

```sh
python -B src/crypto/cipher/chacha20/impl/kotlin/check.py aead
```
