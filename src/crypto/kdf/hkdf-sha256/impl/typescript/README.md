# HKDF-SHA-256 in TypeScript

`extract`, `expand` and `derive` implement RFC 5869 using ABC's TypeScript
HMAC-SHA-256. Extract returns a 32-byte PRK. An omitted salt is expressed as
`null`. Expand accepts PRKs of at least 32 bytes and output lengths from
zero through 8,160 bytes. The expansion loop uses a single-byte block counter
and returns newly allocated output.

The tests cover Appendix A cases 1 and 3, empty output, longer PRKs, malformed
inputs, and the 255th block. Positive-length comparisons use Node's native HKDF. Zero output has its own test.
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)

```sh
node --test src/crypto/kdf/hkdf-sha256/impl/typescript/hkdf.test.mts
```

Source-level refinement, side-channel evaluation, key erasure and production
qualification remain open.

## Public-input timing

On Node 24.12.0 and a Windows x64 i7-12700K workstation, the median of five
warmed batches was 20.2 µs per call with a 64-byte IKM, 13-byte salt, 17-byte info and 64-byte output.
The median for Node's native comparator on the same workload was 6.66 µs.
