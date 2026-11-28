# X25519 in Go

This module exposes the RFC 7748 exchange using Go's standard native
`crypto/ecdh` X25519 implementation. `NewPrivateKey` accepts a raw
32-byte scalar whose entropy comes from the caller. The resulting
read-only state caches the corresponding public key. `PublicKey`
returns its 32-byte coordinate. `SharedSecret` accepts a 32-byte peer
coordinate and returns the raw shared secret.
[RFC 7748 §§5–6](https://www.rfc-editor.org/rfc/rfc7748.html#section-5) · [Curve25519 design paper](https://doi.org/10.1007/11745853_14)

The native Go provider clamps the scalar, masks bit 255 of the peer
coordinate, and processes noncanonical coordinates modulo the field
prime. The API rejects all-zero shared secrets with `ErrInvalidPeer`
and returns zero output on error. The surrounding protocol supplies
peer authentication, transcript binding and key derivation. The
Go provider's FIPS 140-only policy refuses X25519 initialization.

The tested provider is Go 1.24.9. Its installed
`src/crypto/ecdh/x25519.go` SHA-256 was
`7d0987369fd91551ff8da8ba08e2b551058301f3132d9da67a763bcc4696454d`.
The pinned source uses Go's Edwards25519 field arithmetic and the
RFC 7748 Montgomery ladder. The wrapper introduces no alternate
arithmetic or fallback provider. Complete source refinement, compiled
leakage and key erasure for the selected runtime remain open.
[Go 1.24.9 X25519 source](https://github.com/golang/go/blob/go1.24.9/src/crypto/ecdh/x25519.go) · [Go 1.24.9 field implementation](https://github.com/golang/go/tree/go1.24.9/src/crypto/internal/fips140/edwards25519/field)

Tests check both public keys and both shared-secret directions from
RFC 7748 §6.1, as well as the 1- and 1,000-iteration vectors from
§5.2. They also check 14 low-order encodings, including bit-255 aliases,
4 accepted encodings of the basepoint and the complete set of 32
aliases of one clamped scalar. Go 1.24.9 passes on Windows amd64 and
386. Node 24.12 and OpenSSL 3.5.4 independently compare 146 public and
shared-secret outcomes.
[RFC 7748 §5.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-5.2) · [RFC 8410 encoding for the independent provider](https://www.rfc-editor.org/rfc/rfc8410.html#section-4)

```sh
go test -C src/crypto/agreement/x25519/impl/go -count=1 -v ./...
go test -C src/crypto/agreement/x25519/impl/go -run '^$' -bench '^BenchmarkSharedSecret$' -benchtime 100ms -count 5
```

Use Go 1.24.9 to reproduce the provider under test. Node is required
for the provider comparison. The RFC and peer-validation tests run
with Go alone.

On Windows amd64 with an Intel Core i7-12700K, the median of five
shared-secret measurements was 28.342 µs. The benchmark reuses the
local private-key object and imports the raw peer coordinate for each
operation. The Go runtime reported 128 bytes across three allocations
per operation.
