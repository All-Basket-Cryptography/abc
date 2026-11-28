# Kotlin PBKDF2-HMAC-SHA-256

`org.allbasket.abc.kdf.pbkdf2sha256.kotlin.Pbkdf2Sha256` derives bytes using
the portable Kotlin HMAC and SHA-256 cores. It accepts password and salt
byte arrays, a `Long` iteration count in `1..2^32-1`, and a positive
output length that fits a JVM byte array. Long passwords are normalized
once before the PRF loop. The output is a fresh array. Callers set work
and allocation limits before accepting untrusted lengths or iteration counts.
[RFC 8018 § 5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2)

Select Kotlin JVM 2.1.21 with `ABC_KOTLIN_HOME` or `--kotlin-home` and
JDK 17 with `ABC_JAVA_HOME`, `--jdk`, or `PATH`.

```sh
python -B src/crypto/kdf/pbkdf2-hmac-sha256/impl/kotlin/check.py --output .abc/pbkdf2-sha256-kotlin-native
```

The offline checker builds separate SHA-256, HMAC and PBKDF2 JARs and
runs a separate consumer against them. Windows amd64 with JDK 17.0.12
passed two RFC 7914 vectors, including 80,000 iterations, 45 comparisons
based on SunJCE HMAC, and invalid input and ownership checks.
Source-to-Lean refinement, JVM timing evidence, performance benchmarks
and key-state erasure remain open. [RFC 7914 § 11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)
