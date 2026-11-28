# X25519 in JavaScript

The per-profile entry point is [`x25519.mjs`](x25519.mjs). The adapter delegates the cryptographic primitive to Node's linked OpenSSL.

Derive a public key or shared secret from 32-byte inputs. The peer coordinate is masked and reduced modulo 2²⁵⁵−19. Low-order input yields a failed exchange. Bind the key exchange to the calling protocol.

Use the pinned [provider setup](../../../../providers/ecmascript/README.md), then run this command from the repository root.

```sh
node --test src/crypto/agreement/x25519/impl/javascript/x25519.test.mjs
```

The RFC test checks public keys, agreement, coordinate aliases and low-order rejection.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [RFC 7748 §§ 5 and 6.1](https://www.rfc-editor.org/rfc/rfc7748.html)
