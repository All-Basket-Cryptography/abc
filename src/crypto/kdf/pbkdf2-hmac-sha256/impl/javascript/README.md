# PBKDF2-HMAC-SHA-256 in JavaScript

`derive(password, salt, iterations, length)` implements RFC 8018 PBKDF2 with
ABC's JavaScript HMAC-SHA-256. It accepts byte buffers and requires a positive
32-bit iteration count. The output length is positive and limited by the
32-bit block index and by available memory. The API returns newly allocated
output. [RFC 8018 §5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2)

The tests use the 64-byte RFC 7914 vector and 73 independent host comparisons.
They exercise multiple iterations, embedded zero bytes, long passwords,
partial output blocks and the block-index carry from 255 to 256. Test iteration
counts are chosen for coverage. [RFC 7914 §11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)

```sh
node --test src/crypto/kdf/pbkdf2-hmac-sha256/impl/javascript/pbkdf2.test.mjs
```

Source-level refinement, side-channel evaluation, key erasure and production
qualification remain open.

## Public-input timing

On Node 24.12.0 and a Windows x64 i7-12700K workstation, the median of five
warmed batches was 625 µs per call with a 16-byte password, 13-byte salt, 100 iterations and 32-byte output.
The median for Node's native comparator on the same workload was 15.1 µs.
