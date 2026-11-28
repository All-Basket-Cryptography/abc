# Argon2id v1.3 in JavaScript

The per-profile entry point is [`argon2id.mjs`](argon2id.mjs). The adapter delegates the cryptographic primitive to Node's linked OpenSSL.

Derive a tag from password and salt bytes with explicit passes, lanes, output length and caller memory budget. Optional secret and associated data are byte strings. The budget charges the RFC-rounded matrix allocation plus output bytes and excludes provider overhead.

Use the pinned [provider setup](../../../../providers/ecmascript/README.md), then run this command from the repository root.

```sh
node --test src/crypto/kdf/argon2id/impl/javascript/argon2id.test.mjs
```

The RFC test exercises secret and associated data, memory rounding, and the exact budget boundary. The suite also compares 24 parameter sets with portable Rust.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [RFC 9106 §§ 3 and 5.3](https://www.rfc-editor.org/rfc/rfc9106.html)
