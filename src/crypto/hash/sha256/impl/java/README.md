# Pure Java SHA-256

`org.allbasket.abc.hash.sha256.Sha256` implements the whole-byte SHA-256 algorithm directly in Java. The implementation uses Java word arithmetic, a reusable message schedule, and explicit big-endian input and output. It has no native library or cryptographic-provider dependency. [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

Use `Sha256.hash(byte[])` for one-shot hashing or create a streaming instance and call `update(byte[])` or `update(byte[], offset, length)`. `digest()` returns a new 32-byte snapshot and leaves the message available for further updates. Slices are validated before state changes. The whole-byte length limit is (2^{61}-1) bytes. Share one instance across threads only with external synchronization.

## Reproduction

Use JDK 17 and Python from the repository root. Select a JDK with `--jdk` or `ABC_JAVA_HOME`, or place JDK 17 on `PATH`.

```sh
python -B src/crypto/hash/sha256/impl/java/check.py --output .abc/sha256-java-native
```

Both compiler and consumer checks require JDK 17. The checker compiles with `--release 17 -encoding UTF-8 -Xlint:all -Werror`, builds `abc-sha256-pure-java.jar`, then compiles and executes a separate consumer against that JAR. The JDK SHA-256 provider is used by the consumer as the independent oracle. The result report records the source, consumer and artifact digests, toolchain, oracle, and counts.

## Checked scope

The Windows amd64 run passed on Oracle JDK `17.0.12+8-LTS-286` using the `SUN 17` oracle. It passed three known answers, 154 one-shot comparisons, 1,042 streaming snapshots, the padding boundaries, and array ownership and validation checks. The length-limit tests exercise the checked counter operation at its boundary. JVM source-to-specification refinement and target-specific security evidence remain open.
