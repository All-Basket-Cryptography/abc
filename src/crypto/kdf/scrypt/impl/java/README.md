# Java scrypt

The Java SDK implements Salsa20/8, BlockMix, and ROMix and calls
the independent Java PBKDF2-HMAC-SHA-256 core for the two RFC
derivation steps. Pass raw password and salt bytes, cost `N`, block
size `r`, lane count `p`, and the required output length in bytes.
The result belongs to the caller.
[RFC 7914 §§2–6](https://www.rfc-editor.org/rfc/rfc7914.html#section-2)

```java
import org.allbasket.abc.kdf.scrypt.Scrypt;

long bytes = (long) Scrypt.workspaceSize(cost, blockSize, parallel) + keyBytes;
byte[] key = Scrypt.derive(password, salt, cost, blockSize, parallel, keyBytes, bytes);
```

`workspaceSize` reports `128*r*(N + p + 2) + 128` bytes for the
five word arrays and the byte lanes. The ROMix history is reused
for every lane, and BlockMix alternates between two lane arrays.
The adapter verifies the workspace plus output against the caller's
`memoryLimit` before allocating work arrays. The budget counts primary
array payloads and result bytes. JVM object headers, PBKDF2 temporary
objects, and remaining heap capacity are outside this count. The
workspace and output are each capped at `Integer.MAX_VALUE - 8`.
The array cap also implies the RFC's `r*p` bound.

The SDK rejects malformed parameters, preserves caller inputs, and
clears its work arrays at source level after derivation. ROMix uses
data-dependent table reads.
[RFC 7914 §14](https://www.rfc-editor.org/rfc/rfc7914.html#section-14)

```sh
python -B src/crypto/kdf/scrypt/impl/java/check.py --language java
```

On Oracle JDK 17.0.12, a separately built consumer
loaded the scrypt, PBKDF2, HMAC, and SHA-256 JARs. It passed three RFC
known answers and 144 additional comparisons with CPython 3.13.14 and
OpenSSL 3.0.21. Every vector ran at its exact array budget and rejected
a budget one byte smaller. Use `--output` to retain the four JARs
and receipt.
[RFC 7914 §12](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)

Lean checks checked multiplication, the work plus output bound,
the low word of Integerify, and the alternating-buffer schedule.
The shared model proves scatter and table bounds. Full source
refinement, compiled leakage evidence, and comparative performance
measurements remain open.
[Lean JVM bounds](ScryptJvmBounds.lean),
[Shared Lean model](../../spec/ScryptBounds.lean)
