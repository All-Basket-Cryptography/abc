# TypeScript ChaCha20

`block` takes a 32-byte key, a 12-byte nonce and a 32-bit counter.
`applyKeystream` updates the supplied byte view after checking that the
counter range admits every block. The state words use unsigned 32-bit
typed-array arithmetic. The standalone stream cipher requires a
protocol that authenticates messages and assigns unique key/nonce
pairs. [RFC 8439 §2.3](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3)

```sh
node --test src/crypto/cipher/chacha20/impl/typescript/chacha20.test.mts
```

The suite compares the RFC block vector and 144 OpenSSL ciphertexts.
It tests the final counter, rejected lengths and caller-buffer bounds.
Inputs are `Uint8Array` views backed by `ArrayBuffer`.
Full source refinement and runtime leakage qualification remain open.
