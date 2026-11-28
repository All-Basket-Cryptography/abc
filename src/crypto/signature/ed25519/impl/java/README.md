# Java Ed25519

The Java SDK derives a 32-byte public key or a 64-byte pure Ed25519
signature from a 32-byte seed. The SDK signs the exact message bytes
and returns caller-owned arrays. `verifyStrict` accepts raw public key,
message, and signature bytes and returns a Boolean.
[RFC 8032 §5.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1)

```java
import org.allbasket.abc.signature.ed25519.Ed25519;

byte[] publicKey = Ed25519.publicKey(seed);
byte[] signature = Ed25519.sign(seed, message);
boolean verified = Ed25519.verifyStrict(publicKey, message, signature);
```

Strict verification decodes the public key `A` and signature point
`R`, rejects noncanonical or invalid points, and doubles each
decoded point three times to test `[8]P = 0`. Both small-order points
and scalars `S ≥ L` are rejected before SunEC checks the signature
equation. The wrapper operates on publicly supplied inputs during
these point and scalar checks. Keep input arrays stable for each call.
[RFC 8032 §§5.1.2–5.1.4](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.2),
[RFC 8032 §5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7)

Signing and public-key derivation use the built-in SunEC provider
from `jdk.crypto.ec`. Public-key derivation adapts the provider's
one-time 32-byte seed draw in its Ed25519 key generator. The adapter
fails if the generator requests a different seed length, requests
the seed twice, or reports a seed different from the caller's seed.
This behavior was checked against the local Oracle JDK
`17.0.12+8-LTS-286` source archive and runtime. The runtime module
image and VM fingerprints appear in the test receipt.
[JDK provider documentation](https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html),
[JDK key-pair generator](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPairGenerator.html)

```sh
python -B src/crypto/signature/ed25519/impl/java/check.py --language java
```

Using JDK 17, the isolated consumer matched 99 independent Node
24.12.0/OpenSSL 3.5.4 vectors, including three RFC answers. It checked
12 invalid point encodings in both `A` and `R`, malformed lengths, the
scalar boundary, same-name provider replacement, and two identity
cases that the tested SunEC baseline accepted. The SDK rejected both
identity cases. Use `--output` to retain the JAR and receipt and
`--expect-modules-sha256` to require the chosen runtime image.
[RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1),
[RFC 8410 key encodings](https://www.rfc-editor.org/rfc/rfc8410.html)

Lean checks the two field constants, bounds on `S`, the extended
coordinate identity before field reduction, and the three-step
cofactor schedule assuming group doubling. Full decoding and
group-law refinement, the provider proof, compiled leakage evidence,
and comparative performance measurements remain open.
[Lean arithmetic model](Ed25519JvmModel.lean)
