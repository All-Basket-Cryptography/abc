# AES-256 in JavaScript

`new Aes256(key)` consumes a 32-byte key and owns the expanded round schedule.
`encrypt(block)` and `decrypt(block)` return new 16-byte arrays. They take
fixed-length views backed by an ArrayBuffer and use the FIPS 197 column
order. The portable core computes the byte substitution in GF(2^8)
without keyed lookup tables. Use the block primitive inside an authenticated
construction.

The test checks two published AES-256 vectors and 256 generated cases against
Node/OpenSSL in both directions. Auxiliary Lean models cover substitution
and field squaring. This JavaScript source and runtime still require full refinement
and compiled-target leakage analysis.

- [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final)

Run with Node.js 24 from the repository root.

```sh
node --test src/crypto/cipher/aes256/impl/javascript/aes256.test.mjs
```
