# PBKDF2-HMAC-SHA-256 in Python

`derive(password, salt, iterations, length)` implements RFC 8018 PBKDF2 with
ABC's Python HMAC-SHA-256. It accepts byte buffers and requires a positive
32-bit iteration count. The output length is positive and limited by the
32-bit block index and by available memory. The API returns newly allocated
output. [RFC 8018 §5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2)

The tests use the 64-byte RFC 7914 vector and 73 independent host comparisons.
They exercise multiple iterations, embedded zero bytes, long passwords,
partial output blocks and the block-index carry from 255 to 256. Test iteration
counts are chosen for coverage. [RFC 7914 §11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)

```sh
python -B -m unittest discover -s src/crypto/kdf/pbkdf2-hmac-sha256/impl/python -p test_pbkdf2.py
```

Source-level refinement, side-channel evaluation, key erasure and production
qualification remain open.

## Public-input timing

On CPython 3.13.14 and a Windows x64 i7-12700K workstation, the median of five
warmed batches was 43.3 ms per call with a 16-byte password, 13-byte salt, 100 iterations and 32-byte output.
The median for the native-backed oracle on the same workload was 33.9 µs.
