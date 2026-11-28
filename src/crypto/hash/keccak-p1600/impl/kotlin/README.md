# Kotlin Keccak-p[1600,24]

The shared native Kotlin core implements all 24 rounds and the 136-byte
byte-oriented sponge. It stores 64-bit lanes in `x + 5*y` order, uses
little-endian words and applies the SHA3-256 or SHAKE256 domain during
finalization. SHA3 returns the first 32 output bytes. SHAKE readers
own an independent finalized state and output cursor.
[FIPS 202 §§3–4](https://csrc.nist.gov/pubs/fips/202/final)

The checker uses JDK 17 and the Kotlin 2.1.21 distribution. Set
`ABC_KOTLIN_HOME` or pass `--kotlin-home` and select the JDK with
`--jdk` or `ABC_JAVA_HOME`.

```sh
python -B src/crypto/hash/keccak-p1600/impl/java/check.py --language kotlin --algorithm keccak-p1600
```

The isolated consumer checks all 25 output lanes of the XKCP zero-state
example. Use `--output` to retain the tested JAR.
[XKCP reference output](https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt)

Lean checks the complete word-oriented permutation and block-oriented
sponge model. Exact Kotlin source refinement and compiled-target
leakage and performance qualification remain open.
[Lean model](../../spec)
