# Python AES-256-GCM

The native Python AES-256 core and bitwise GHASH implement the SP 800-38D
profile with 32-byte keys, 12-byte nonces and full 16-byte tags.
`seal_detached(key, nonce, plaintext, aad=b"")` returns ciphertext and tag.
`open_detached(key, nonce, ciphertext, tag, aad=b"")` raises `InvalidTag`
before decrypting a failed input. The opener verifies and decrypts the
same immutable ciphertext snapshot. Assign a fresh nonce for each seal
under the same key.

Two NIST vectors, 112 independent OpenSSL cases and authentication failure
tests cover the byte interface. Lean verifies separate counter and tag
reduction conditions. Python's whole composition, integer timing and
target behavior still need proof.

- [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [NIST GCM worked examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)
- [NIST GCM vectors](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes)

Run from the repository root with Python 3 and Node.js 24.

```sh
python -B -m unittest discover -s src/crypto/aead/aes256-gcm/impl/python -p test_aes256gcm.py
```
