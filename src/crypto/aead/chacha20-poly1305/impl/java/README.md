# Java ChaCha20-Poly1305

This JDK 17 implementation exposes detached authenticated encryption
with 32-byte keys, 12-byte nonces, and 16-byte tags. Use a unique nonce
for every encryption under a key. The SDK returns caller-owned arrays.
[RFC 8439 §§2.6–2.8](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8)

```java
import org.allbasket.abc.aead.chacha20poly1305.ChaCha20Poly1305;

var sealed = ChaCha20Poly1305.seal(key, nonce, aad, plaintext);
byte[] opened = ChaCha20Poly1305.open(key, nonce, aad, sealed.ciphertext(), sealed.tag());
```

`open` returns `null` for authentication failure, including an incorrect
tag length. Wrong key or nonce lengths raise an argument error. The
implementation authenticates a private ciphertext copy before decrypting
the same copy and leaves caller inputs intact. The caller must keep
input arrays stable for each call.

The Java ChaCha20 core uses counter zero to derive the Poly1305 key and
starts the payload at counter one. The Java Poly1305 core absorbs AAD,
ciphertext, their boundary padding, and both little-endian byte lengths.
The IETF payload bound is 274,877,906,880 bytes. A single Java array has
a lower limit.
[Java ChaCha20](../../../../cipher/chacha20/impl/java),
[Java Poly1305](../../../../mac/poly1305/impl/java)

```sh
python -B src/crypto/aead/chacha20-poly1305/impl/java/check.py
lean -DwarningAsError=true src/crypto/aead/chacha20-poly1305/impl/java/ChaCha20Poly1305JavaBounds.lean
```

The checker builds three separate SDK JARs and compiles a consumer
against them. On JDK 17.0.12, sealing and opening matched 202
Node 24.12.0/OpenSSL 3.5.4 cases, including the RFC known answer
and padding and block boundaries. The consumer exercised 23
authentication rejections and malformed key and nonce sizes.
Use `--output` to retain the tested JARs and receipt.
[RFC 8439 §2.8.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2)

Lean checks padding, transcript alignment, length-field bounds, and
separation of payload counters from the key-derivation counter for
Java array lengths. Exact Java source refinement, compiled leakage
evidence, and comparative timing measurements remain open.
[Lean Java bounds](ChaCha20Poly1305JavaBounds.lean)
