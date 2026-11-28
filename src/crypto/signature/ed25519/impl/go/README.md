# Native Go Ed25519

`PublicKey` derives a 32-byte compressed public key from a 32-byte seed.
`Sign` takes the same seed and signs the message in pure Ed25519 mode,
returning 64 signature bytes. These APIs delegate key expansion and
signing to Go's `crypto/ed25519`. They accept fixed-size arrays and
clear the adapter-owned expanded key buffer before returning.
[RFC 8032 §§5.1.5–5.1.6](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5)

`VerifyStrict` first checks that the public point A and the signature
commitment R decode and re-encode byte-for-byte in canonical form.
For each point, it computes the cofactor multiple `[8]P` and requires a
nonidentity result. Go's provider then checks canonical scalar S and its
uncofactored pure Ed25519 verification equation. This point policy
admits mixed-order points that also satisfy the signature equation.
`ErrPublicKey` identifies a rejected A. `ErrSignature` identifies a
rejected signature or a mismatch with the message.
[RFC 8032 §§5.1.3 and 5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7) · [Pinned Go verifier](https://github.com/golang/go/blob/go1.24.9/src/crypto/internal/fips140/ed25519/ed25519.go)

The point operations use the native Go module
`filippo.io/edwards25519` at `v1.2.0`, commit
`b182a6575cfd9f4fbb1d1d4e487a6b00a3ec06f7`. The module archive's
Go checksum is
`h1:crnVqOiS4jqYleHd9vaKZ+HKtHfllngJIiOpNpoJsjo=`.
The leaf locks the module and manifest checksums in `go.sum`.
[Pinned point source](https://github.com/FiloSottile/edwards25519/tree/b182a6575cfd9f4fbb1d1d4e487a6b00a3ec06f7)

Run with Go 1.24.9 and Node 24.12.0. Populate the checksum-verified
module cache before running offline. In a separate consumer, require
the ABC module and replace it with a pinned local copy of this directory.

```sh
go mod download -C src/crypto/signature/ed25519/impl/go
go test -C src/crypto/signature/ed25519/impl/go -count=1 ./...
node src/crypto/signature/ed25519/impl/go/verify.mjs
go test -C src/crypto/signature/ed25519/impl/go -run '^$' -bench 'Benchmark(VerifyStrict|ProviderVerify)' -benchmem -benchtime=200ms -count=3 -cpu=1
```

The Go unit tests cover three RFC vectors, malformed and low-order points,
noncanonical scalar inputs, and altered messages. The Node tool checks
96 public keys and exact deterministic signatures against OpenSSL 3.5.4,
with each provider verifying the other's signature. Go tests and that
oracle passed for Windows amd64 and 386 with cgo disabled. The isolated
source consumer also passed the first RFC vector.
[RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1) · [RFC 8410 key encoding](https://www.rfc-editor.org/rfc/rfc8410.html)

On Windows amd64 with an Intel Core i7-12700K, three single-worker
4,096-byte verification runs gave a median of 48.746 µs for
`VerifyStrict` and 43.720 µs for Go's verifier. Both reported zero heap
allocations per operation. Exact source refinement, secret lifetime across
the provider call chain and compiled-target leakage analysis remain open.
