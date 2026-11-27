# ChaCha20-Poly1305 in Go

This standalone module composes ABC's Go ChaCha20 and Poly1305 cores. The
detached interface accepts a 32-byte key and 12-byte nonce, and uses a
fixed 16-byte tag. `SealDetached` writes ciphertext to the equally long
destination prefix. `OpenDetached` authenticates the complete ciphertext
and associated data before releasing plaintext. Authentication and
input validation errors preserve the destination. The API accepts overlapping source,
destination, and associated-data slices. The caller is responsible for
nonce uniqueness under each key.
[RFC 8439 §§2.6, 2.8 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.6)

The RFC example and 174 bidirectional OpenSSL 3.5.4 comparisons cover
empty input, block boundaries, arbitrary data and associated data.
Go 1.24.9 passes on Windows amd64 and 386. Modified tag bytes, incorrect
associated data, changed ciphertext and short buffers exercise the
destination-preservation contract. Node 24.12 is used for the independent
provider comparison. The maintained Lean properties cover padding, the
payload counter range, and the modular recurrence of the Poly1305 Go
arithmetic model. Full Go source refinement and target-specific leakage
evidence remain open.
[AEAD length model](../../spec/ChaCha20Poly1305Lengths.lean) · [Poly1305 Go model](../../../../mac/poly1305/impl/go/Poly1305GoModel.lean)

On Windows amd64 with an Intel Core i7-12700K, the median of five runs
for a 4 KiB message with 16 bytes of associated data was 15.64 µs,
with zero allocations and a distinct nonce per call. The measurement
applies to this compiler, host and detached API.

```sh
go test -C src/crypto/aead/chacha20-poly1305/impl/go -count=1 -v ./...
go test -C src/crypto/aead/chacha20-poly1305/impl/go -run '^$' -bench '^BenchmarkSeal4096$' -benchtime 150ms -count 5
```

Applications using the research modules from a local checkout must map
the AEAD, ChaCha20, and Poly1305 module paths to their corresponding
`impl/go` directories in the application's own `go.mod`. The dependency
module's local replacements apply to its own builds.
