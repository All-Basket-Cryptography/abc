# Kotlin BLAKE2b

`org.allbasket.abc.hash.blake2b.kotlin.Blake2b` implements sequential,
unkeyed BLAKE2b on the JVM with digests of 1–64 bytes. The parameter
word binds the digest size. Compression uses little-endian words,
12 rounds and a 128-bit byte counter. A complete last block stays
pending for the final flag. The module uses Kotlin and the JDK.
[RFC 7693 §§2–3](https://www.rfc-editor.org/rfc/rfc7693.html#section-2)

Construct `Blake2b(digestSize)` to stream at a selected size. The
default is 64 bytes. `update(input, offset, length)` absorbs a range,
`digest()` returns an owned snapshot and `reset()` clears the stream
at the same size. `Blake2b.hash(input, digestSize)` is the one-shot
API. Invalid ranges and counter overflow leave the stream unchanged.
Serialize operations on a shared instance.

The verifier compiles the module and a separate Kotlin JAR consumer.
On Windows x64 with Kotlin 2.1.21 and Oracle JDK 17.0.12 it passed five
published known answers, 139 OpenSSL comparisons, 697 CPython
`hashlib.blake2b` comparisons, 841 prefix snapshots and 4,926 streaming
splits. Tests additionally exercise invalid ranges and the 128-bit
counter carry and overflow. On the same Intel Core i7-12700K, 1 MiB
BLAKE2b-512 throughput medians were 487 MiB/s for Kotlin and 1,170 MiB/s
for OpenSSL through CPython.
[RFC 7693 Appendix A](https://www.rfc-editor.org/rfc/rfc7693.html#appendix-A) · [BLAKE2 project known answers](https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json)

```sh
python -B src/crypto/hash/blake2b/impl/kotlin/check.py --jdk "$ABC_JAVA_HOME" --kotlin-home "$ABC_KOTLIN_HOME"
python -B src/crypto/hash/blake2b/impl/kotlin/check.py --jdk "$ABC_JAVA_HOME" --kotlin-home "$ABC_KOTLIN_HOME" --benchmark
```

Lean proves final-block retention in the buffer model. Kotlin source
refinement and compiled-target timing analysis remain open.
[Lean buffer model](../../spec/Blake2bBuffer.lean) · [BLAKE2 design paper](https://www.blake2.net/blake2_lncs.pdf)
