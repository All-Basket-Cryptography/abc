# Poly1305 in Kotlin

`Poly1305` takes a fresh 32-byte key for one message. Call `update` with
whole arrays or public ranges and `finish` for the full 16-byte tag.
Finishing closes the instance. `authenticate` provides one-shot use.
[RFC 8439 §§2.5 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5)

The separately compiled consumer checks eight RFC answers at every
split, 512 expanded-polynomial cases, 32 OpenSSL EVP-MAC cases and
input bounds. The Lean reduction model covers the mathematical
recurrence. Correspondence with Kotlin limbs and JVM timing remain open.
[Lean reduction model](../../spec/Poly1305Reduction.lean)

Select the offline Kotlin JVM 2.1.21 distribution with
`ABC_KOTLIN_HOME` and JDK 17 with `ABC_JAVA_HOME` or the path. Select the
OpenSSL executable with `ABC_OPENSSL` when needed.
Use `--output` to keep the independently checked JAR.

```sh
python -B src/crypto/cipher/chacha20/impl/kotlin/check.py poly1305
```
