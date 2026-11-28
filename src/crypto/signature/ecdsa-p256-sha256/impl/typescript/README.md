# Deterministic ECDSA P-256 with SHA-256 in TypeScript

The per-profile entry point is [`ecdsa_p256.mts`](ecdsa_p256.mts). The adapter calls the pinned Noble source package. Runtime tests run on Node.js.

Use a 32-byte private scalar, SEC 1 compressed or uncompressed public keys for verification, and 64-byte IEEE P1363 signatures. The SDK returns the uncompressed key and preserves the original S value in deterministic output.

Use the pinned [provider setup](../../../../providers/ecmascript/README.md), then run this command from the repository root.

```sh
node --test src/crypto/signature/ecdsa-p256-sha256/impl/typescript/ecdsa_p256.test.mts
```

The RFC tests check both SHA-256 signatures, including a high-S output, and public-key encoding.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [RFC 6979 § 3.2 and Appendix A.2.5](https://www.rfc-editor.org/rfc/rfc6979.html)
