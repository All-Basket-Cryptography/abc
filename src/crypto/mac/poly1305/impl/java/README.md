# Java Poly1305

The standalone JDK 17 implementation authenticates byte arrays with a
32-byte one-time key and returns a 16-byte tag. Use a fresh key for each
message. The ChaCha20-Poly1305 construction derives a fresh Poly1305
key from the message nonce.
[RFC 8439 §§2.5–2.6](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5)

```java
import org.allbasket.abc.mac.poly1305.Poly1305;

byte[] tag = Poly1305.authenticate(oneTimeKey, message);
```

For streaming, create a `Poly1305` in a try-with-resources block, call
`update` on each byte-array range, then call `finish` once. Invalid
ranges leave the context intact. The implementation consumes ranges
before returning and copies the pending tail. Finishing returns a
caller-owned tag and closes the context. Closing clears its working
arrays at Java source level. Use each context from one thread.

The core uses five 26-bit limbs, signed 64-bit products within the
proved bounds, and a fixed word schedule for final reduction.

```sh
python -B src/crypto/mac/poly1305/impl/java/check.py
lean -DwarningAsError=true src/crypto/mac/poly1305/impl/java/Poly1305JavaWords.lean
```

The checker builds a standalone JAR and compiles a separate consumer
against it. With JDK 17.0.12, the consumer passed 438 outputs against an
independent Python integer model, including eight RFC vectors, and
7,381 two-part splits. Passing `--openssl` selected 42 cases to
cross-check with OpenSSL 3.5.4. Use `--output` to retain the JAR and
receipt.
[RFC 8439 §2.5.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5.2),
[RFC 8439 Appendix A.3](https://www.rfc-editor.org/rfc/rfc8439.html#appendix-A.3)

The Lean model proves the RFC clamp mask, signed product and carry
bounds under the stated limb bounds, selection for both reduction
mask values, and the bound for the final tag-word addition. Source
refinement, runtime side-channel evidence, and comparative timing
measurements remain open.
[Lean word arithmetic](Poly1305JavaWords.lean),
[Shared reduction model](../../spec/Poly1305Reduction.lean)
