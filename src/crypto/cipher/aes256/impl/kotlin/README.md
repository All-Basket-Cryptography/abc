# Kotlin AES-256

The Kotlin/JVM 2.1.21 targeting JDK 17 adapter applies AES-256 to one 16-byte block
with a 32-byte key. `encryptBlock` and `decryptBlock` return caller-owned
arrays. Use each initialized context from one thread. ECB is used as
the JCA transform for a single raw block. Use a separate AEAD profile to
encrypt messages.
[FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)

```kotlin
import org.allbasket.abc.cipher.aes256.kotlin.Aes256

val cipher = Aes256(key)
val encrypted = cipher.encryptBlock(block)
```

The adapter uses the built-in SunJCE provider from `java.base`.
The consumer verified rejection of a replacement provider registered
under the same name. The Windows amd64 evidence identifies Oracle JDK
`17.0.12+8-LTS-286` with `UseAESIntrinsics` and `UseGHASHIntrinsics`
enabled. The receipt records the module image and VM fingerprints.
`--expect-modules-sha256` enforces a chosen JDK image during verification.
Exact refinement of the provider, compiled leakage evidence, and
comparative performance measurements remain open.
[Oracle JDK provider reference](https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html),
[Oracle JDK 17.0.12 release notes](https://www.oracle.com/java/technologies/javase/17-0-12-relnotes.html)

The checker builds an independent JAR and compiles a JVM consumer
against it. Select Kotlin 2.1.21 using `ABC_KOTLIN_HOME` or
`--kotlin-home`. `--output` retains the tested artifact and receipt.

```sh
python -B src/crypto/cipher/aes256/impl/java/check.py --algorithm aes256 --language kotlin
```

The isolated consumer matched 514 independent Node 24.12.0/OpenSSL 3.5.4
cases in both directions, including two published known answers.
It also exercised invalid key and block lengths and repeated use of an
initialized context.
[NIST AES-256 examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core256.pdf)
