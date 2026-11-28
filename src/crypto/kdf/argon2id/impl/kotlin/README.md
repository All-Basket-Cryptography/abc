# Kotlin Argon2id

The byte-oriented SDK fixes Argon2id version `0x13` (1.3). Pass raw
password, salt, secret and associated-data bytes, memory in KiB,
iterations, lanes, tag size and a memory budget in bytes. Empty
arrays select an absent secret or associated data. Input arrays
remain caller-owned, as does the returned tag.
[RFC 9106 §§3.1–3.2](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.1)

`workspaceBytes(memoryKiB, lanes)` accounts for RFC-rounded primary
blocks, the pinned provider's four fill blocks, and one temporary
block. The adapter checks workspace plus tag size before provider
allocation. The calculation covers byte payloads of those buffers.
It leaves JVM object overhead, parameter copies and available heap
capacity outside the count. Salt is at least eight bytes, the tag is
at least four bytes, and memory is at least eight KiB per lane.
The adapter clears builder and parameter copies. The reviewed
provider clears its primary memory after derivation.

The implementation delegates Argon2id to the lightweight API in
`org.bouncycastle:bcprov-jdk18on:1.87`. The archive and source archive
match their published SHA-256 checksums. The SDK JAR requires that
provider on the runtime classpath.
[Exact artifact pin](../java/bcprov.toml),
[Bouncy Castle release](https://github.com/bcgit/bc-java/releases/tag/r1rv87),
[Pinned Argon2 generator](https://github.com/bcgit/bc-java/blob/dd1e61c26066d0793d3f348bf6b4d9b73b701e77/core/src/main/java/org/bouncycastle/crypto/generators/Argon2BytesGenerator.java)

```sh
python -B src/crypto/kdf/argon2id/impl/java/check.py --language kotlin
```

The checker validates the provider archive pin before compiling a
standalone SDK JAR and a separate consumer. Use `--bcprov` or
`ABC_BCPROV_JAR` to select a pre-fetched archive for an offline run.
`--output` retains the SDK JAR and receipt.
Select Kotlin 2.1.21 with `--kotlin-home` or `ABC_KOTLIN_HOME`.

On Oracle JDK 17.0.12, the isolated consumer matched 101 Node
24.12.0/OpenSSL 3.5.4 outputs including the RFC vector with a secret
and associated data. Every case accepted its exact budget and
rejected one byte less.
[RFC 9106 §5.3](https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3)

Lean checks the adapter's integer bounds and budget addition.
Exact source refinement, provider leakage and comparative
performance evidence remain open.
[Lean JVM budget model](../java/Argon2idJvmBudget.lean)
