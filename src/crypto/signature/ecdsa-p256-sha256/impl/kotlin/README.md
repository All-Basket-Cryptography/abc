# Kotlin deterministic ECDSA P-256 with SHA-256

The SDK takes a 32-byte big-endian private scalar in `1 ≤ d < n`.
`publicKey` returns a 65-byte uncompressed SEC 1 point. Verification
accepts compressed and uncompressed SEC 1 points in their exact
canonical form. It rejects infinity, hybrid encodings and points
outside the curve. Signatures are 64-byte P1363 values containing
fixed-width big-endian `r || s`. Both must be in `1..n-1`.
[RFC 6979 Appendix A.2.5](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5),
[NIST P-256 domain parameters](https://csrc.nist.gov/pubs/sp/800/186/final)

The SDK hashes the supplied message with SHA-256 and signs
using Bouncy Castle's deterministic HMAC nonce generator and pinned
P-256 arithmetic. Signing keeps the RFC 6979 `s` value. Verification
accepts `s` and its alternate representative. Returned bytes belong
to the caller. The provider holds immutable scalar temporaries
during an operation.
[RFC 6979 §3.2](https://www.rfc-editor.org/rfc/rfc6979.html#section-3.2)

Use the lightweight API of `org.bouncycastle:bcprov-jdk18on:1.87`.
The SDK JAR requires the pinned provider archive on its runtime classpath.
[Exact archive and source pin](../../../../kdf/argon2id/impl/java/bcprov.toml),
[Pinned provider source](https://github.com/bcgit/bc-java/tree/dd1e61c26066d0793d3f348bf6b4d9b73b701e77)

```sh
python -B src/crypto/signature/ecdsa-p256-sha256/impl/java/check.py --language kotlin
```

The checker compiles a standalone SDK and a separate JAR consumer.
Use `--bcprov` or `ABC_BCPROV_JAR` to select a pre-fetched archive
and `--output` to retain the SDK JAR and receipt.
Select Kotlin 2.1.21 with `--kotlin-home` or `ABC_KOTLIN_HOME`.

On JDK 17.0.12, both RFC signature vectors and the RFC public key
matched. The consumer repeated 50 signatures deterministically and
checked each public key and both signature directions against Node
24.12.0/OpenSSL 3.5.4. It also checked the first and last private
scalars, malformed points, malformed signature scalars, and incorrect
messages.

Lean checks scalar bounds and how the two P1363 fields split.
Exact source refinement, compiled leakage and comparative
performance measurements remain open.
[Lean JVM encoding model](../java/EcdsaP256JvmEncoding.lean)
