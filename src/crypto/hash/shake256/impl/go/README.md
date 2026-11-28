# Go SHAKE256

`New` returns an absorber with `Write` and `Reset`. `Finalize` returns
an independent `io.Reader` starting at offset zero and leaves the
absorber available for further input. Each successful read fills its
destination and advances that reader. `XOF(input, output)` is the
one-shot operation and accepts overlapping input and output slices.
[FIPS 202 §6.2](https://csrc.nist.gov/pubs/fips/202/final)

The Go modules can be used from a separate consumer with both source
modules available at pinned local paths. In the consumer's `go.mod`,
require the SHAKE256 module and replace both it and the Keccak module with
those paths. The leaf's replacement path is for the in-repository build.
The core absorbs with a 136-byte rate and domain byte `0x1f`.
[Core source and module](../../../keccak-p1600/impl/go)

```sh
go test -C src/crypto/hash/shake256/impl/go -count=1 ./...
go test -C src/crypto/hash/shake256/impl/go -run '^$' -bench BenchmarkXOF32 -benchmem -benchtime=200ms -count=3 -cpu=1
```

The suite checks known answers and compares 409 output bytes to Go
`crypto/sha3` for each of 2,234 input splits, crossing the absorption and
output rate boundaries. Lean checks the complete block-oriented sponge
behavior and the split-read list equation. Exact Go source refinement and platform security and
performance qualification remain open.
[NIST secure hashing vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) · [Lean Keccak model](../../../keccak-p1600/spec)

On Windows amd64 with Go 1.24.9 and Intel Core i7-12700K, the median of the
three 4,096-byte input runs with 32 output bytes was 21.689 µs for ABC
and 7.391 µs for `crypto/sha3` using its resettable SHAKE reader. Both
reported zero heap allocations per operation. The native tests also
passed on Windows 386, and the copied modules passed in a separate
offline consumer.
