# Go SHA3-256

`New` returns a `hash.Hash` with byte-aligned `Write`, `Reset` and a
non-destructive `Digest` snapshot. `Sum` appends the 32-byte digest to its
prefix. `Sum256` is the one-shot function. The zero-value absorber is ready
to use. The backend is the ABC Go Keccak-p[1600,24] core with 136-byte
rate and domain byte `0x06`.
[FIPS 202 §6.1](https://csrc.nist.gov/pubs/fips/202/final)

The Go modules can be used from a separate consumer with both source modules
available at pinned local paths. In the consumer's `go.mod`, require the
SHA3-256 module and replace both it and the Keccak module with those paths.
The replacement paths in the leaf manifest are for the in-repository
build. Neither module has a third-party runtime dependency.
[Core source and module](../../../keccak-p1600/impl/go)

```sh
go test -C src/crypto/hash/sha3-256/impl/go -count=1 ./...
go test -C src/crypto/hash/sha3-256/impl/go -run '^$' -bench BenchmarkSum256 -benchmem -benchtime=200ms -count=3 -cpu=1
```

The tests cover the NIST byte-aligned known answers and 2,234 input
splits across nine lengths, comparing one-shot and intermediate digest
snapshots with Go `crypto/sha3`. The Lean model covers byte encoding and
the complete block-oriented sponge behavior.
Exact Go source refinement and platform security and performance
qualification remain open.
[NIST example values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values) · [Lean Keccak model](../../../keccak-p1600/spec)

On Windows amd64 with Go 1.24.9 and Intel Core i7-12700K, the median of the
three 4,096-byte runs was 21.413 µs for ABC and 7.275 µs for `crypto/sha3`.
Both reported zero heap allocations per operation. The native tests also
passed on Windows 386, and the copied modules passed in a separate offline
consumer.
