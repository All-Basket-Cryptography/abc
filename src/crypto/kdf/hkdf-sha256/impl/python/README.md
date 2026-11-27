# HKDF-SHA-256 in Python

`extract`, `expand` and `derive` implement RFC 5869 using ABC's Python
HMAC-SHA-256. Extract returns a 32-byte PRK. An omitted salt is expressed as
`None`. Expand accepts PRKs of at least 32 bytes and output lengths from
zero through 8,160 bytes. The expansion loop uses a single-byte block counter
and returns newly allocated output.

The tests cover Appendix A cases 1 and 3, empty output, longer PRKs, malformed
inputs, and the 255th block. Independent comparisons use Python's native HMAC as the PRF of a test oracle.
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)

```sh
python -B -m unittest discover -s src/crypto/kdf/hkdf-sha256/impl/python -p test_hkdf.py
```

Source-level refinement, side-channel evaluation, key erasure and production
qualification remain open.

## Public-input timing

On CPython 3.13.14 and a Windows x64 i7-12700K workstation, the median of five
warmed batches was 1.41 ms per call with a 64-byte IKM, 13-byte salt, 17-byte info and 64-byte output.
The median for the test construction with native HMAC on the same workload was 5.87 µs.
