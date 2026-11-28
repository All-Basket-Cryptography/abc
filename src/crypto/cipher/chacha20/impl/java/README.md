# Java IETF ChaCha20

The standalone JDK 17 implementation uses 32-byte keys, 12-byte
nonces, and unsigned 32-bit initial block counters. `ChaCha20.block`
returns a 64-byte keystream block. A `ChaCha20` context applies the
keystream in place across arbitrarily split byte-array ranges. Encryption
and decryption use the same method with fresh contexts.
[RFC 8439 §§2.3–2.4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3)

```java
import org.allbasket.abc.cipher.chacha20.ChaCha20;

try (ChaCha20 stream = new ChaCha20(key, nonce, 1)) {
    stream.apply(message);
}
```

Assign a unique nonce per key and authenticate ciphertext at the
protocol layer. For integrated encryption and authentication, use the
separate ChaCha20-Poly1305 profile.
[RFC 8439 §§2.8, 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8)

The counter interface accepts a Java `long` in the interval 0 through
4,294,967,295. `remaining()` reports unused bytes including any part of
the current block. Invalid ranges and requests beyond that capacity
leave state and caller data intact. The caller owns the input and
output arrays. Use each context from one thread. Closing invalidates
the context and clears its working arrays at Java source level.
[JDK 17 ChaCha20 parameters](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/spec/ChaCha20ParameterSpec.html)

```sh
python -B src/crypto/cipher/chacha20/impl/java/check.py
lean -DwarningAsError=true src/crypto/cipher/chacha20/impl/java/ChaCha20StreamingBounds.lean
```

The checker builds a standalone JAR with Java 17 and compiles an
independent consumer against it. `--output` retains the tested JAR
and a receipt. On JDK 17.0.12, it reproduced the RFC block and cipher
vectors and matched SunJCE across 79 cases and 3,959 two-part splits.
It exercises unsigned counters above the signed boundary, consumption
of the last legal block, and preservation of the buffer and cursor
when an update is rejected.
[RFC 8439 block vector](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3.2),
[RFC 8439 encryption vector](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4.2)

The Lean arithmetic model proves that refill preserves capacity, a
nonempty accepted refill has a representable block counter, consuming
bytes subtracts their count, and the reported capacity fits a signed
64-bit value. Java source refinement, compiled side-channel evidence,
and a comparative performance measurement remain open.
[Lean stream bounds](ChaCha20StreamingBounds.lean),
[Lean quarter round](../../spec/ChaCha20QuarterRound.lean)
