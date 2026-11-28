# Go deterministic ECDSA P-256 with SHA-256

This native Go research SDK uses the Go 1.24.9 standard-library ECDSA,
P-256 and SHA-256 core. It accepts a 32-byte big-endian private scalar
with `1 ≤ d < n`. The adapter imports a fixed SEC 1 structure into
`crypto/x509` and rejects zero before import. `PublicKey` returns a
65-byte uncompressed SEC 1 point. `Verify` accepts 33-byte compressed
and 65-byte uncompressed points and rejects other encodings and points
outside the curve.
[Standards for Efficient Cryptography 1 (SEC 1) §§2.3.3–2.3.4, C.4](https://www.secg.org/sec1-v2.pdf) · [P-256 parameters](https://csrc.nist.gov/pubs/sp/800/186/final)

`Sign` hashes the message with SHA-256 and invokes the pinned
`(*ecdsa.PrivateKey).Sign` with a nil random reader and
`crypto.SHA256`. This selects Go's RFC 6979 deterministic signing
route. The adapter converts the provider's DER integers to two
32-byte big-endian fields in IEEE P1363 order `r || s`. Both integers
must be in `1..n-1`. Signing preserves the provider's S representative,
and verification accepts both valid representatives.
[RFC 6979 §§3.2 and A.2.5](https://www.rfc-editor.org/rfc/rfc6979.html#section-3.2) · [Go 1.24.9 signing source](https://github.com/golang/go/blob/go1.24.9/src/crypto/ecdsa/ecdsa.go)

## Reproduction

Use Go 1.24.9, with Node on PATH for the interoperability test. The
library builds with `CGO_ENABLED=0` without external modules.

```sh
go test -C src/crypto/signature/ecdsa-p256-sha256/impl/go -count=1 ./...
go test -C src/crypto/signature/ecdsa-p256-sha256/impl/go -count=1 -tags interop -run '^TestOpenSSLInterop$' -v ./...
go test -C src/crypto/signature/ecdsa-p256-sha256/impl/go -run '^$' -bench '^BenchmarkSDK$' -benchmem -benchtime=300ms -count=3 ./...
```

A separate Go test consumer on Windows amd64 and 386 matched the RFC
public key and both RFC 6979 P-256/SHA-256 signatures. Boundary tests
cover private and signature scalars, unsupported point encodings,
altered messages and both valid S representatives. Node v24.12.0 with
OpenSSL 3.5.4 verified 48 Go signatures, signed 48 messages for Go to
verify, and independently derived the SEC 1 public keys.

On Windows amd64 and a Core i7-12700K, the median SDK times were 11.49 µs
for public key derivation, 34.72 µs for signing 128 bytes, and 52.35 µs
for verifying 128 bytes. Each operation includes public or private key
import. These are measurements for the listed target and API.

Provider and adapter source refinement, compiled-target leakage, and
key-material erasure across the full call chain remain open.
[Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
