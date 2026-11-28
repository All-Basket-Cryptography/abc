# Ed25519 in TypeScript

The per-profile entry point is [`ed25519.mts`](ed25519.mts). Node OpenSSL derives keys and evaluates signatures. Noble checks the public point encoding and small-order policy.

Derive, sign or verify Pure Ed25519 with a 32-byte seed, 32-byte encoded public key and 64-byte signature. Verification rejects noncanonical and small-order A/R, and out-of-range S.

Use the pinned [provider setup](../../../../providers/ecmascript/README.md), then run this command from the repository root.

```sh
node --test src/crypto/signature/ed25519/impl/typescript/ed25519.test.mts
```

The RFC test checks exact signatures and rejects malformed encodings and wrong messages.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [RFC 8032 §§ 5.1 and 7.1](https://www.rfc-editor.org/rfc/rfc8032.html)
