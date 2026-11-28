# Java SHA-512

`org.allbasket.abc.hash.sha512.Sha512` implements byte-oriented SHA-512
directly in Java. It uses fixed-width `long` arithmetic, a reusable
80-word schedule and a two-word byte counter. The counter admits at most
`2^125 - 1` bytes and encodes the bit length as 16 big-endian bytes.
[FIPS 180-4 §§ 4.2.3, 5.1.2, 5.3.5 and 6.4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

`Sha512.hash(byte[])` hashes a whole array. A streaming instance accepts a
whole array or a checked slice, and `digest()` returns an owned 64-byte
snapshot. Rejected updates preserve the message, which remains available
for later updates. Synchronize externally when sharing a stream.

## Reproduction

Use JDK 17 and Python 3.11 or later. Select the JDK with `--jdk`,
`ABC_JAVA_HOME`, or `PATH`.

```sh
python -B src/crypto/hash/sha512/impl/java/check.py --output .abc/sha512-java-native
```

On Windows amd64, Oracle JDK 17.0.12 compiled the library and a separate
JAR consumer with `--release 17 -Xlint:all -Werror`. The consumer passed
three known answers, 157 one-shot comparisons and 1,116 streaming
snapshots against the JCA `SUN 17` SHA-512 provider. A `BigInteger` oracle
checked 1,005 synthetic length-counter and encoding cases, including
rejection beyond the maximum. Range rejection and caller-array ownership
also passed. The report records the checks and source, consumer and JAR
digests. JVM source-to-specification refinement and evidence for other
targets remain open. [NIST Secure Hashing test resources](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)
