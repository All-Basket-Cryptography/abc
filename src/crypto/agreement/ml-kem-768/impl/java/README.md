# Java ML-KEM-768

The SDK imports a 64-byte private `d || z` seed, returns a 1,184-byte
encapsulation key, and produces 1,088-byte ciphertexts and 32-byte
shared secrets. `generateKey` and `encapsulate` use the JVM CSPRNG.
`encapsulate` checks every public-key coefficient against 3,329 before
passing the key to the provider.
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)

Decapsulation checks ciphertext length and returns a 32-byte result.
For malformed content of the correct length, it returns the FIPS 203
implicit-rejection secret. Use the `AutoCloseable` handle to limit the
provider private object's lifetime. Closing invokes the provider's
destruction method and invalidates the handle. The caller manages
input seeds, ciphertexts and result arrays.

The SDK uses the lightweight API of `org.bouncycastle:bcprov-jdk18on:1.87`.
Place the pinned provider archive on the runtime classpath.
[Exact artifact and source pin](../../../../kdf/argon2id/impl/java/bcprov.toml),
[Pinned source](https://github.com/bcgit/bc-java/tree/dd1e61c26066d0793d3f348bf6b4d9b73b701e77)

```sh
python -B src/crypto/agreement/ml-kem-768/impl/java/check.py --language java
```

The checker uses a separately compiled SDK JAR and consumer. Use
`--bcprov` or `ABC_BCPROV_JAR` to supply the pinned archive offline.
Use `--output` to keep the tested SDK JAR and receipt.

On JDK 17.0.12, the tests matched two NIST seed-to-public-key vectors
and rejected the noncanonical encapsulation-key vector at the SDK
boundary. Four ACVP vectors exercised the provider's deterministic
encapsulation and expanded-key decapsulation in the test consumer.
The SDK accepts private seeds, and the expanded-key import-negative
fixture belongs to the upstream test suite. The consumer exercised
12 bidirectional Node 24.12.0/OpenSSL 3.5.4 exchanges, 12 same-length
implicit-rejection checks that also matched SHAKE256, and four
randomized key generation roundtrips.
[Pinned ACVP projection](../../spec/acvp.json),
[NIST ACVP source](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files)

Lean proves the nibble mask, coefficient and offset bounds, and
modulus threshold in the encoding model. Exact provider refinement,
compiled leakage, full-call-chain erasure and comparative performance
evidence remain open.
[Lean coefficient model](MlKem768JvmEncoding.lean)
