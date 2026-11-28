# AES-256-GCM in TypeScript

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
- [NIST GCM vectors](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes)

Run with Node.js 24 from the repository root.

```sh
node --test src/crypto/aead/aes256-gcm/impl/typescript/aes256gcm.test.mts
```
