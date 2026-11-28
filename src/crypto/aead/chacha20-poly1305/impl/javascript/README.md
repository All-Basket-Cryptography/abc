# ChaCha20-Poly1305 in JavaScript

`seal(key, nonce, aad, plaintext)` returns a new ciphertext and a 16-byte tag. `open(key, nonce, aad, ciphertext, tag)` returns plaintext after authentication or `null` for an invalid tag. Use 32-byte keys and unique 12-byte nonces per key. The AEAD runs on the same-language ChaCha20 and Poly1305 and derives its one-time key from counter zero. The tests cross-check Node/OpenSSL and the RFC example.

```sh
node --test src/crypto/aead/chacha20-poly1305/impl/javascript/chacha20poly1305.test.mjs
```

Inputs are `Uint8Array` views backed by `ArrayBuffer`. The module uses
fixed-length views of the underlying bytes and rejects shared, detached,
and out-of-bounds input. Opening authenticates and decrypts the same
bytes without invoking caller-defined view methods or getters. The tests
cover this behavior alongside standards vectors and differential execution.
Target and runtime timing qualification remains open.

A Windows x64 i7-12700K with Node 24.12.0 and OpenSSL 3.5.4 measured
138.58 µs per 4 KiB seal with 16 bytes of AAD. Node/OpenSSL measured
6.38 µs in the same seven-trial median with 1,000 calls per trial.

```sh
node src/crypto/aead/chacha20-poly1305/impl/javascript/benchmark.mjs
```

- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
