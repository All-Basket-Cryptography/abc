# Kotlin AES-256-GCM

The Kotlin/JVM 2.1.21 targeting JDK 17 adapter uses 32-byte keys, 12-byte nonces, and
16-byte detached tags. Use a unique nonce for every encryption under a
key. Successful calls return caller-owned arrays. `open` returns
`null` for an invalid tag and never returns unauthenticated plaintext.
The adapter supplies AAD first and invokes the provider's one-shot
`doFinal` for authenticated decryption. Wrong key or nonce lengths
raise an argument error.
[SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final),
[JDK Cipher](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/Cipher.html)

```kotlin
import org.allbasket.abc.aead.aes256gcm.kotlin.Aes256Gcm

val cipher = Aes256Gcm(key)
val sealed = cipher.seal(nonce, aad, plaintext)
val result = cipher.open(nonce, aad, sealed.ciphertext(), sealed.tag())
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
python -B src/crypto/cipher/aes256/impl/java/check.py --algorithm aes256-gcm --language kotlin
```

The isolated consumer matched 274 independent Node 24.12.0/OpenSSL 3.5.4
seal and open cases, including NIST GCM-AES256 examples #1 and #5.
It exercised 23 authentication rejections covering altered key,
nonce, AAD, ciphertext, each tag byte, and malformed tag lengths.
The JCA combined representation limits payload bytes to
`Integer.MAX_VALUE - 16` before the JVM's allocation limits. The
adapter arithmetic model checks the bound against SP 800-38D, the
length-field widths, and the detached layout.
[NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf),
[Lean JVM bounds](../java/Aes256GcmJvmBounds.lean)
