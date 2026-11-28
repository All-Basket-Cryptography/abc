# ChaCha20 in Kotlin

`ChaCha20.block`, `xor`, and `xorInto` implement the IETF profile with a
32-byte key, a 12-byte nonce, and an unsigned 32-bit initial counter.
`xorInto` accepts exact in-place arrays and leaves trailing bytes intact.
Use each nonce and counter range only once under a key.
[RFC 8439 §§2.3–2.4 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3)

The separately compiled consumer checks two RFC answers and 144
OpenSSL cases, including empty input, the final counter, and rejected
counter or buffer sizes. The Lean quarter-round and counter properties
cover the model. Complete Kotlin refinement and JVM timing remain open.
[ChaCha20 specification](../../spec/)

Select the offline Kotlin JVM 2.1.21 distribution with
`ABC_KOTLIN_HOME` and JDK 17 with `ABC_JAVA_HOME` or the path.
Use `--output` to keep the independently checked JAR.

```sh
python -B src/crypto/cipher/chacha20/impl/kotlin/check.py chacha20
```
