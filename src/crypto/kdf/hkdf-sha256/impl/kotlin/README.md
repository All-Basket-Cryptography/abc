# Kotlin HKDF-SHA-256

`org.allbasket.abc.kdf.hkdfsha256.kotlin.HkdfSha256` implements extract,
expand and derive using the portable Kotlin HMAC and SHA-256 cores.
An omitted salt uses 32 zero bytes. Expand accepts a PRK of at least
32 bytes and returns 0–8160 bytes in a fresh array. Pass an empty array
for empty info. [RFC 5869 §§ 2.2–2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.2)

Select Kotlin JVM 2.1.21 with `ABC_KOTLIN_HOME` or `--kotlin-home` and
JDK 17 with `ABC_JAVA_HOME`, `--jdk`, or `PATH`.

```sh
python -B src/crypto/kdf/hkdf-sha256/impl/kotlin/check.py --output .abc/hkdf-sha256-kotlin-native
```

The offline checker builds separate SHA-256, HMAC and HKDF JARs and runs a
separate consumer against them. Windows amd64 with JDK 17.0.12 passed
RFC 5869 cases A.1 and A.3, 70 comparisons based on SunJCE HMAC, and
invalid length and maximum output checks. Source-to-Lean refinement,
JVM timing evidence, performance benchmarks and key-state erasure
remain open. [RFC 5869 Appendix A](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)
