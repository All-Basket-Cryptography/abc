# ChaCha20-Poly1305 in TypeScript

`seal(key, nonce, aad, plaintext)` returns a new ciphertext and a 16-byte tag. `open(key, nonce, aad, ciphertext, tag)` returns plaintext after authentication or `null` for an invalid tag. Use 32-byte keys and unique 12-byte nonces per key. The AEAD runs on the same-language ChaCha20 and Poly1305 and derives its one-time key from counter zero. The tests cross-check Node/OpenSSL and the RFC example.

```sh
node --test src/crypto/aead/chacha20-poly1305/impl/typescript/chacha20poly1305.test.mts
```

Inputs are `Uint8Array` views backed by `ArrayBuffer`. Shared buffers are
rejected so another thread cannot change the ciphertext between verification
and decryption. The evidence covers standards vectors and differential
execution. Target and runtime timing qualification remains open.

A Windows x64 i7-12700K with Node 24.12.0 and OpenSSL 3.5.4 measured
138.63 µs per 4 KiB seal with 16 bytes of AAD. Node/OpenSSL measured
6.46 µs in the same seven-trial median with 1,000 calls per trial.

```sh
node src/crypto/aead/chacha20-poly1305/impl/javascript/benchmark.mjs
```

- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
