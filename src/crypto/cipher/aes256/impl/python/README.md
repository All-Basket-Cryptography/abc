# Python AES-256

The native Python block operation implements the 14-round AES-256 schedule
and both directions without using a cipher provider. `Aes256(key)` takes
a 32-byte key and retains its own expanded bytes. `encrypt(block)` and
`decrypt(block)` take a 16-byte buffer and return immutable bytes.
Use the block operation through an authenticated construction.

The suite checks two public vectors and 256 cases against independent
Node/OpenSSL encryption and decryption. Lean verifies the separate field
and substitution models. A proof relating Python's full source and
interpreter timing to the specification remains open.

- [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)
- [SP 800-38A block examples](https://csrc.nist.gov/pubs/sp/800/38/a/final)

Run from the repository root with Python 3 and Node.js 24.

```sh
python -B -m unittest discover -s src/crypto/cipher/aes256/impl/python -p test_aes256.py
```
