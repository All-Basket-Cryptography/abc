# Kotlin Pure deterministic ML-DSA-65

The SDK derives a 1,952-byte public key and signs with a 32-byte seed.
Signatures are 3,309 raw bytes. Messages may be empty. A binary context
may be 0–255 bytes. The signer selects Pure ML-DSA's message domain
and uses the provider's deterministic mode without a randomness input.
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

Verification checks the exact widths, nondecreasing hint
endpoints, strictly increasing indices within each polynomial and
zero bytes in the unused hint tail. The provider checks the remaining
signature conditions. Verification returns a Boolean.
The adapter copies the seed before handing it to the provider and
destroys the provider's key object after use. This preserves the
caller's original seed because the provider zeroes its retained input
array on destruction.
[Pinned source](https://github.com/bcgit/bc-java/tree/dd1e61c26066d0793d3f348bf6b4d9b73b701e77)

The SDK uses the lightweight API of `org.bouncycastle:bcprov-jdk18on:1.87`.
Place the pinned provider archive on the runtime classpath.
[Exact artifact and source pin](../../../../kdf/argon2id/impl/java/bcprov.toml)

```sh
python -B src/crypto/signature/ml-dsa-65/impl/java/check.py --language kotlin
```

The checker builds an SDK JAR and separately compiles the consumer.
Use `--bcprov` or `ABC_BCPROV_JAR` for an offline provider archive.
Use `--output` to retain the SDK JAR and receipt.
Select Kotlin 2.1.21 with `--kotlin-home` or `ABC_KOTLIN_HOME`.

On JDK 17.0.12, four selected NIST ACVP vectors exercised key generation,
verification and the provider's exact expanded-key signing vector.
The production SDK accepts 32-byte seeds. The consumer also checked
16 bidirectional Node 24.12.0/OpenSSL 3.5.4 cases with contexts up to
255 bytes, caller seed preservation, and five malformed hint shapes.
Configure `ABC_MLDSA_OPENSSL` to run the 12 exact deterministic
OpenSSL CLI comparisons. All 12 passed with OpenSSL 3.5.4.
[Pinned ACVP projection](../../spec/acvp-fips204-sample.json),
[NIST ACVP sources](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files)

Lean checks context width, hint index and delimiter bounds, and
uniqueness for strictly ordered hints. Exact implementation
refinement, rejection-sampling and compiled leakage proofs, full
key erasure and comparative performance measurements remain open.
[Lean encoding model](../java/MlDsa65JvmEncoding.lean)
