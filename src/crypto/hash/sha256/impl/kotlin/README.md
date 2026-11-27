# Kotlin SHA-256

`org.allbasket.abc.hash.sha256.kotlin.Sha256` implements the whole-byte SHA-256 algorithm directly in Kotlin. It uses the JVM's 32-bit integer operations and a reusable message schedule. The core uses the Kotlin standard library and has no JNI, Rust, Java SHA-256 implementation, or cryptographic-provider dependency. [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

Use `Sha256.hash(ByteArray)` for one-shot hashing. Streaming instances accept a full byte array or a validated slice. `digest()` returns an owned 32-byte snapshot and keeps the stream available for more input. A rejected update preserves the state. Each instance requires external synchronization if shared across threads.

## Reproduction

Use Kotlin JVM compiler 2.1.21 and JDK 17. Set `ABC_KOTLIN_HOME` to the Kotlin distribution containing `lib/kotlin-compiler.jar` and `lib/kotlin-stdlib.jar`, or pass `--kotlin-home`. Select JDK 17 through `ABC_JAVA_HOME`, `--jdk`, or `PATH`.

```sh
python -B src/crypto/hash/sha256/impl/kotlin/check.py --output .abc/sha256-kotlin-native
```

The checker builds a Kotlin research JAR with `-Xjdk-release=17` and executes a separate consumer against it and the pinned compiler's standard library. The JDK SHA-256 provider is the test oracle. The report records compiler, runtime, source and artifact digests, and comparison counts.

## Checked scope

The Windows amd64 run used Android Studio's Kotlin 2.1.21 compiler, Oracle JDK `17.0.12+8-LTS-286`, and the `SUN 17` oracle. It passed three known answers, 154 one-shot comparisons, 1,030 streaming snapshots, and validation and array ownership checks. JVM source-to-specification refinement and other target evidence remain open.
