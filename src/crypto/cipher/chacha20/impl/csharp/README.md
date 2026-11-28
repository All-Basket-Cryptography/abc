# ChaCha20 in C#

`Abc.Cryptography.ChaCha20` exposes `ChaCha20Cipher.Block` and
`ChaCha20Cipher.Xor` over byte spans with a 32-byte key, a 12-byte nonce,
and a 32-bit initial counter. `Xor` accepts disjoint or exact in-place
buffers. A shifted overlap or counter overflow throws before output
changes. Use each nonce and counter range only once under a key.
[RFC 8439 §§2.3–2.4 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3)

The offline NuGet consumer checks two RFC answers, 144 OpenSSL ciphertexts,
the final usable counter, buffer boundaries, and exact in-place operation.
Run the consumer with .NET SDK 10.0.404 and Node OpenSSL.

```sh
python -B src/crypto/cipher/chacha20/impl/csharp/check.py chacha20
```

The Lean quarter-round and counter models cover the corresponding
algorithm properties. Refinement of this C# core and qualification of
JIT output and target timing remain open.
[ChaCha20 specification](../../spec/)
