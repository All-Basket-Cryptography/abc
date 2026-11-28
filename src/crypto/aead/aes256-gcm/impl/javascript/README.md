# AES-256-GCM in JavaScript

`seal(key, nonce, aad, plaintext)` returns a new ciphertext and 16-byte
tag. `open(key, nonce, aad, ciphertext, tag)` authenticates the exact input
byte view before running counter-mode decryption and returns plaintext or
`null` for a bad tag. Use a fresh 12-byte nonce for each seal under the
same 32-byte key. The module uses same-language table-free AES and GHASH
with four unsigned 32-bit words. Shared and detached backing stores fail
validation.

The test checks published vectors and 216 bidirectional cases against
Node/OpenSSL. The shared Lean models cover counter constraints and the
tag-reduction condition. Complete composition and target timing proofs
remain open.

- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [NIST GCM worked examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)
- [NIST GCM vectors](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes)

Run with Node.js 24 from the repository root.

```sh
node --test src/crypto/aead/aes256-gcm/impl/javascript/aes256gcm.test.mjs
```

An i7-12700K on Windows x64, Node 24.12.0 and OpenSSL 3.5.4 measured a
3,902.56 µs median for the portable 4 KiB seal and 8.19 µs for Node/OpenSSL
with 16 bytes of AAD. Reproduce both measurements with the same harness.

```sh
node src/crypto/aead/aes256-gcm/impl/javascript/benchmark.mjs
```
