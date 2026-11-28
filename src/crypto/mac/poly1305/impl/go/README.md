# Poly1305 in Go

This module implements the RFC 8439 one-time authenticator. `Sum` operates
on one complete message. `New`, `Update`, and `Finalize` offer incremental
authentication. A completed state returns the same tag on subsequent
finalization and rejects further updates. Each distinct message requires
a fresh one-time 32-byte key. Keep the returned state under one owner's
control and use a separate state for each message.
[RFC 8439 §2.5 and Appendix A.3](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5) · [The Poly1305-AES message-authentication code](https://doi.org/10.1007/11502760_3)

The fixed-width core uses five radix-`2^26` limbs, full-width unsigned
products, and masked subtraction. Lean 4.31.0 proves the five weighted product
columns, bounds for the intermediate arithmetic, and equivalence of the
carry and block transitions to the modular recurrence for any finite
sequence of bounded parsed blocks. The model also verifies the
final-reduction threshold and the mask for each carry bit. Correspondence
with the complete Go source, compiler behavior, and key-lifetime
properties require further evidence.
[Go arithmetic model](Poly1305GoModel.lean)

Go 1.24.9 on Windows amd64 and 386 matched the RFC example and seven
appendix reduction vectors at every split point. An independent
arbitrary-precision implementation checked 2,126 messages and their
streaming forms. Tests exercise zero-length input, key clamping, final
state, and ownership of the supplied buffers.

```sh
go test -C src/crypto/mac/poly1305/impl/go -count=1 -v ./...
lean src/crypto/mac/poly1305/impl/go/Poly1305GoModel.lean
```
