# ChaCha20 in Python

The standalone module uses Python integers reduced to 32-bit words
for the additions, XOR operations, and rotations of RFC 8439.
It accepts contiguous byte buffers containing a 32-byte key and a
12-byte nonce. `block` emits one keystream block, `xor` returns a new
transformed byte string, and `xor_into` writes the matching destination
prefix. The latter supports overlap and validates inputs before
writing. Use distinct nonces under each key. Separate block-aligned
calls must also advance the counter past already processed blocks.
[RFC 8439 §§2.1–2.4 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.1) · [ChaCha design paper](https://cr.yp.to/chacha/chacha-20080128.pdf)

The tests check both RFC answers and 144 independent OpenSSL 3.5.4
ciphertexts through Node. They cover the final block counter,
counter overflow, aliasing, and preservation on rejected inputs.
The repository's Lean models cover the RFC word operations and
counter bound. Python execution, allocation behavior, and
complete source refinement require separate evidence.
[Lean quarter-round model](../../spec/ChaCha20QuarterRound.lean) · [Lean counter model](../../spec/ChaCha20Counter.lean)

```sh
python -B -m unittest discover -s src/crypto/cipher/chacha20/impl/python -p test_chacha20.py -v
```
