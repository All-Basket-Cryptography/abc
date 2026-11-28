# Python SHA-512

`Sha512.update` absorbs one-dimensional byte buffers and `Sha512.digest`
returns a non-destructive 64-byte snapshot. `Sha512.reset` starts an empty
message. The function `sha512` returns a one-shot digest. The byte bound is
2^125−1. A byte length or buffer shape error leaves the digest unchanged.
[FIPS 180-4 §§4.1.3, 4.2.3, 5.1.2, 5.3.5 and 6.4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

The runtime uses Python integers with explicit 64-bit modular reduction.
Tests use CPython's `hashlib.sha512` as an independent oracle. Exact source
refinement and runtime qualification remain open.
[NIST secure hashing vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing)

```sh
python -B -m unittest discover -s src/crypto/hash/sha512/impl/python -p test_sha512.py -v
```
