# Kotlin SHA-512

The JVM core implements FIPS 180-4 SHA-512 in Kotlin with fixed-width
`Long` arithmetic and a rolling 16-word schedule. `update` accepts a
whole array or a checked slice. `digest` returns an independent output
and permits more updates. The two-word counter admits at most
`2^125 - 1` message bytes before emitting a 128-bit big-endian trailer.
[FIPS 180-4 §§4–6](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

Run with JDK 17 and the Kotlin JVM 2.1.21 compiler distribution.

```sh
python -B src/crypto/hash/sha512/impl/kotlin/check.py --kotlin-home <kotlin-distribution> --output .abc/sha512-kotlin
```

The checker builds a JAR and a separate JDK 17 consumer. It exercises
three known answers, all splits around the padding and compression block
boundaries, offset ranges, and independent JCA comparison. Lean checks
the schedule-ring and counter arithmetic models. JVM source and runtime
refinement remain open. [Lean schedule model](../../spec/Sha512Ring.lean)
