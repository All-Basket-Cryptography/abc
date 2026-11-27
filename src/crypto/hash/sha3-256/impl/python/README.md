# Python SHA3-256

`sha3_256(data)` returns a one-shot digest. `Sha3_256().update(data)`
absorbs more bytes, `digest()` returns a 32-byte snapshot, and
`reset()` starts a new message. The inputs are one-dimensional buffers
with one-byte items. Strided inputs are read in their logical order and
caller buffers can be reused after each update. The Python backend uses
the 136-byte rate and domain byte `0x06`.
[FIPS 202 §6.1](https://csrc.nist.gov/pubs/fips/202/final)

Place `abc_sha3_256.py` and the shared `abc_keccak_p1600.py` in the
consumer's import directory and import `abc_sha3_256` with Python 3.10 or
newer.
[Shared core](../../../keccak-p1600/impl/python)

```sh
python -B -m unittest discover -s src/crypto/hash/sha3-256/impl/python -p test_sha3_256.py -v
```

The tests check NIST byte-aligned known answers, buffer validation and
2,234 split traces, including digest snapshots compared with
`hashlib.sha3_256`. The Lean model covers byte encoding and complete
block-oriented sponge behavior. Exact Python
source refinement and runtime timing evidence remain open.
[NIST example values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values) · [Lean Keccak model](../../../keccak-p1600/spec)

A separate Python `-I` consumer using copied sources passed. On Windows
amd64 with CPython 3.13.14 and OpenSSL 3.0.21, the median with a
4,096-byte message was 5.886 ms for ABC and 6.615 µs for `hashlib`,
using three `timeit.repeat` batches of 100 calls and 12,000 calls
respectively.
