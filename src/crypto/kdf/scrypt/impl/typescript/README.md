# TypeScript scrypt

The native RFC 7914 KDF composes same-language PBKDF2-HMAC-SHA-256,
Salsa20/8, BlockMix and ROMix. Call `derive(password, salt, options)` with
byte views and integer `cost` (N), `blockSize` (r), `parallel` (p),
`length` (output bytes), and `memoryLimit` (bytes).

`workspaceSize(N, r, p)` returns the combined size of the lane data,
ROMix table, BlockMix arrays and 128 bytes of state. The required memory
limit also includes the returned key. This budget measures the listed
buffers. The engine and PBKDF2 retain their own allocation overhead.
The arrays fit a portable 31-bit allocation profile and working arrays
are cleared after derivation. ROMix makes password-dependent memory reads.

The suite checks two RFC vectors, 144 independent OpenSSL comparisons and
boundary errors. The shared Lean proofs cover the BlockMix permutation and
ROMix indices. Complete source refinement and runtime leakage evidence
remain open.

```sh
node --test src/crypto/kdf/scrypt/impl/typescript/scrypt.test.mts
```

- [RFC 7914 §§ 2–6](https://www.rfc-editor.org/rfc/rfc7914.html#section-2)
- [RFC 7914 § 12](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)
- [Shared specification and proof scope](../../spec/README.md)
