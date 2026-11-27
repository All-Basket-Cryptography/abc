# Python SHAKE256

`shake256(data, size)` returns a one-shot output with a nonnegative byte
length. `Shake256().update(data)` absorbs additional one-dimensional
byte buffers and `finalize()` creates an independent reader without
consuming the absorber. A reader's `read(size)` returns a new byte
string. Its `readinto(buffer)` fills a writable contiguous single-byte
buffer and returns the number of output bytes. Each call advances only
that reader. The core uses a 136-byte rate and domain byte `0x1f`.
[FIPS 202 §6.2](https://csrc.nist.gov/pubs/fips/202/final)

Place `abc_shake256.py` and the shared `abc_keccak_p1600.py` in the
consumer's import directory and use Python 3.10 or newer.
[Shared core](../../../keccak-p1600/impl/python)

```sh
python -B -m unittest discover -s src/crypto/hash/shake256/impl/python -p test_shake256.py -v
```

The tests compare 409 output bytes at each of 2,234 input splits against
`hashlib.shake_256`, including separate readers, output boundaries and
rejected calls preserving the reader offset. Lean checks complete
block-oriented sponge behavior and the split-read list equation. Exact Python source refinement and
runtime timing evidence remain open.
[NIST secure hashing vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) · [Lean Keccak model](../../../keccak-p1600/spec)

A separate Python `-I` consumer using copied sources passed. On Windows
amd64 with CPython 3.13.14 and OpenSSL 3.0.21, the median with a
4,096-byte message and 32 output bytes was 5.825 ms for ABC and 6.587 µs
for `hashlib`, using three `timeit.repeat` batches of 100 calls and
12,000 calls respectively.
