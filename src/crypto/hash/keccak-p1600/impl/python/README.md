# Python Keccak-p[1600,24]

`abc_keccak_p1600.py` provides the shared permutation and sponge for the
native Python SHA3-256 and SHAKE256 modules. Each round computes theta, rho,
pi, chi and iota on 25 lanes. Rotations explicitly maintain the 64-bit
domain of Python integer words. The sponge absorbs and encodes 136-byte
blocks in little-endian order.
[FIPS 202 §§3–4 and §6](https://csrc.nist.gov/pubs/fips/202/final)

Copy `abc_keccak_p1600.py` alongside either corresponding profile module
into the consumer's import directory. The Python 3.10 or newer build
uses only the standard library.

```sh
python -B -m unittest discover -s src/crypto/hash/keccak-p1600/impl/python -p test_keccak.py -v
```

The test checks all 25 output lanes against the XKCP zero-state example.
Lean checks the word-oriented round and sponge model against individual
bit equations. Source refinement and leakage analysis for the Python
runtime are open.
[XKCP permutation vectors](https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt) · [Lean model](../../spec)
