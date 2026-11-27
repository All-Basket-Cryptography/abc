# Kotlin HMAC-SHA-256

`org.allbasket.abc.mac.hmacsha256.kotlin.HmacSha256` uses the independent Kotlin
SHA-256 core for key normalization and both HMAC passes. `authenticate`
returns the full 32-byte tag. A streaming instance accepts a full array or a
checked slice and provides owned tag snapshots. A rejected update preserves
the stream. [RFC 2104 § 2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2)

Select the Kotlin JVM 2.1.21 distribution with `ABC_KOTLIN_HOME` or
`--kotlin-home`. Select JDK 17 with `ABC_JAVA_HOME`, `--jdk`, or `PATH`.

```sh
python -B src/crypto/mac/hmac-sha256/impl/kotlin/check.py --output .abc/hmac-sha256-kotlin-native
```

The checker builds the independent SHA-256 and HMAC Kotlin JARs and runs a
separate consumer. The Windows amd64 run with JDK 17.0.12 passed three RFC
4231 known answers, 153 one-shot SunJCE comparisons, 312 streaming
snapshots, and validation and array ownership checks. The report records
the runtime, source digests and artifact digests. Source refinement,
compiled-target leakage and key erasure remain open. [RFC 4231 § 4](https://www.rfc-editor.org/rfc/rfc4231.html#section-4)
