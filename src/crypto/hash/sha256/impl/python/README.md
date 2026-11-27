# Portable Python SHA-256

`abc_sha256.py` implements the FIPS 180-4 message schedule, rounds, padding and
encoding with Python integers and byte buffers. It exposes `sha256(data)` and a
`Sha256` context with `update`, `digest` and `reset`. Digests are immutable bytes.
The input accepts one-dimensional byte buffers, including strided views. The
context retains its own pending bytes. `digest` takes a snapshot, and oversized
updates raise `OverflowError` before modifying the context. [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

CPython 3.13.14 on Windows amd64 passed three fixed digests, 997 boundary splits,
128 seeded binary inputs checked against `hashlib.sha256`, buffer and reset
tests, and a synthetic counter-boundary test. [NIST worked examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf)

```sh
python -B -m unittest discover -s src/crypto/hash/sha256/impl/python -p test_sha256.py
```

Source-level refinement, independent review and SDK integration remain open.

## Public-input timing

On a shared Windows amd64 workstation with an Intel Core i7-12700K, the
median of five warmed `timeit` batches was 205 µs for 64 bytes and 6.71 ms for
4,096 bytes. CPython's native `hashlib.sha256` took 0.417 µs and 2.21 µs on
the same deterministic inputs. The pure Python batches used 500 and 25 calls,
with 20,000 and 10,000 calls for the native comparator. Both timings include
constructing the context and obtaining its digest.
