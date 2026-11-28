# Java X25519

The Java SDK accepts raw 32-byte scalars and peer coordinates and
returns raw 32-byte public keys and shared secrets. The adapter clears
bit 255 of the peer input and reduces the little-endian coordinate
modulo `2^255 - 19`. SunEC clamps the scalar and performs the X25519
ladder. `sharedSecret` returns `null` for a low-order peer or an all-zero
result. Invalid key widths raise an argument error. Returned arrays
belong to the caller.
[RFC 7748 §§5–6](https://www.rfc-editor.org/rfc/rfc7748.html#section-5)

```java
import org.allbasket.abc.agreement.x25519.X25519;

byte[] localPublic = X25519.publicKey(privateBytes);
byte[] shared = X25519.sharedSecret(privateBytes, peerPublic);
```

The calling protocol supplies CSPRNG-generated private bytes,
authenticates the exchange, and derives session keys using a KDF with
the required transcript binding.
[RFC 7748 §7](https://www.rfc-editor.org/rfc/rfc7748.html#section-7)

The implementation uses the built-in SunEC provider from
`jdk.crypto.ec`. The Windows amd64 test used Oracle JDK
`17.0.12+8-LTS-286` and records JDK module-image and VM fingerprints.
Use `--expect-modules-sha256` to require a specific module image at
verification time.
[JDK SunEC provider](https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html),
[JDK key specification](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/spec/XECPublicKeySpec.html)

```sh
python -B src/crypto/agreement/x25519/impl/java/check.py --language java
```

The checker builds a standalone SDK JAR and separately compiles a
consumer. It passed the RFC Alice/Bob public keys and shared secret in
both directions, the first and 1,000th iteration results, 196 Node
24.12.0/OpenSSL 3.5.4 comparisons, 32 scalar clamp aliases, three
peer aliases, 14 low-order rejections, and a same-name provider
replacement rejection. `--output` retains the artifact and receipt.
[RFC 7748 §§5.2 and 6.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-5.2),
[RFC 8410 key encodings](https://www.rfc-editor.org/rfc/rfc8410.html)

Lean checks the field range, coordinate aliases, and high-bit
masking in a mathematical model. The Java/Kotlin source refinement,
the SunEC ladder proof, compiled leakage evidence, and comparative
performance measurements remain open.
[Lean encoding model](X25519JvmEncoding.lean)
