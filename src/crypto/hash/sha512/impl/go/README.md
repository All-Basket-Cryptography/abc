# Go SHA-512

The independent FIPS 180-4 SHA-512 core follows the ABC Go hash API.
`New` opens a stream, `Update` absorbs bytes, and `Digest` returns a
non-destructive 64-byte snapshot. The zero-value `Hasher` is ready to
use. `Reset` clears the message state and `Sum512` hashes a single slice.
The two-word byte count accepts at most 2^125−1 bytes across updates. An
overflowing update returns `ErrMessageTooLong` and leaves the state unchanged.
[FIPS 180-4 §§4.1.3, 4.2.3, 5.1.2, 5.3.5 and 6.4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

The compression function uses a 16-word schedule ring and Go's fixed-width
rotate operation. [Lean schedule model](../../spec/Sha512Ring.lean)

Test oracles use the Go standard library. Exact source refinement and deployment
qualification remain open. [NIST secure hashing vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing)

```sh
go test -C src/crypto/hash/sha512/impl/go -count=1 ./...
go test -C src/crypto/hash/sha512/impl/go -run '^$' -bench BenchmarkSum512 -benchmem -benchtime=250ms -count=3
```

Windows amd64 tests and vet passed with Go 1.24.9. The tests also passed
on Windows 386. On an Intel Core i7-12700K, the medians of three Windows
amd64 runs were 279.0 ns for 32 bytes and 8.289 µs for 4,096 bytes. The
Go standard library took 182.3 ns and 4.821 µs on the same inputs. All
four cases reported zero heap allocations.
