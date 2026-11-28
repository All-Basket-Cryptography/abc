# ChaCha20-Poly1305 in Python

This module composes the ABC Python ChaCha20 and Poly1305 cores.
`seal_detached(key, nonce, plaintext, aad)` returns ciphertext and a
full 16-byte tag. `open_detached(key, nonce, ciphertext, tag, aad)`
returns authenticated plaintext. The key is 32 bytes and the nonce
is 12 bytes. Use a distinct nonce for each encryption under a key.
[RFC 8439 §§2.6–2.8 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.6)

`seal_into` and `open_into` write only the destination prefix and allow
overlap with caller buffers. Mutable inputs are copied to immutable
snapshots. Opening compares the complete tag with `hmac.compare_digest`
before decrypting the verified snapshot. Invalid tags and ciphertext
leave destination buffers untouched.

The tests cover the RFC known answer, 174 bidirectional OpenSSL 3.5.4
comparisons through Node, boundaries, aliasing, changes to mutable
buffers during authentication, and rejection before decryption.
The repository's Lean length model covers padding and the counter
domain. Complete Python source refinement, interpreter timing and
runtime key erasure remain open.
[Lean AEAD length model](../../spec/ChaCha20Poly1305Lengths.lean)

Run from the repository root so the sibling Python modules resolve.

```sh
python -B -m unittest discover -s src/crypto/aead/chacha20-poly1305/impl/python -p test_chacha20_poly1305.py -v
```
