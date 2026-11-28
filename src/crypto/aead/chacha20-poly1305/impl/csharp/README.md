# ChaCha20-Poly1305 in C#

`Abc.Cryptography.ChaCha20Poly1305` exposes the detached `Seal` and
`TryOpen` APIs over byte spans. The module uses the ABC C# ChaCha20 and
Poly1305 packages with a 32-byte key, a 12-byte nonce and a 16-byte tag.
Use a unique nonce for each seal under the same key.
[RFC 8439 §§2.6–2.8 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.6)

`Seal` accepts disjoint or exact in-place payload buffers and requires
a separate tag destination. `TryOpen` authenticates a ciphertext copy
and then decrypts that same copy. Authentication failure returns false
before writing to the plaintext destination. Opening allows overlap and
writes only the plaintext prefix. Give each call stable input spans and
exclusive use of its output.

The offline NuGet consumer checks the RFC known answer, 174 bidirectional
OpenSSL cases, wrong tag lengths, each changed tag byte, modified ciphertext
and AAD, and buffer boundaries. The 4 KiB seal benchmark with 16 bytes
of AAD measured 28.43 µs for this implementation and 7.96 µs for the
platform .NET provider on Windows x64 with an Intel i7-12700K. Each is
the median of seven trials with 1,000 calls per trial.

```sh
python -B src/crypto/cipher/chacha20/impl/csharp/check.py aead --benchmark
```

The Lean length model covers padding and the counter domain.
Source refinement, JIT behavior, and runtime key-erasure qualification
remain open.
[Lean AEAD length model](../../spec/ChaCha20Poly1305Lengths.lean)
