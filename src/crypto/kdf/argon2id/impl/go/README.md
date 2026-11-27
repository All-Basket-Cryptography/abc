# Go Argon2id v1.3

The native Go profile accepts raw password, salt, secret and associated
data. The core implements Argon2id version `0x13`, with data-independent
addressing for the first two slices of the first pass and data-dependent
addressing after that. It computes lanes serially at each slice barrier.
The initial hash and variable-length output use the shared Go BLAKE2b
implementation.
[RFC 9106 §§3.1–3.6](https://www.rfc-editor.org/rfc/rfc9106.html#section-3) · [Go BLAKE2b](../../../../hash/blake2b/impl/go)

`NewParameters(memoryKiB, passes, lanes)` checks the RFC work-factor
domain and rounds the memory down to a multiple of four blocks per lane.
It preserves the original requested memory for the initial hash and
checks the rounded byte size against the platform's `int` limit.
`WorkspaceBlocks()` tells the caller how many 1 KiB blocks to supply to
`Derive`. The raw tag buffer may hold 4 to `2^32 - 1` bytes where
representable, and the salt must contain at least eight bytes. Empty
secret and associated data values represent omission. Validation errors
preserve both output and workspace. Extra workspace remains untouched.
The caller owns workspace lifetime and erasure after derivation.

To consume the library outside the repository, require the Argon2id
module and replace it and its Go BLAKE2b dependency with pinned local
source copies in the consumer's `go.mod`.

```sh
go test -C src/crypto/kdf/argon2id/impl/go -count=1 ./...
node src/crypto/kdf/argon2id/impl/go/verify.mjs
go test -C src/crypto/kdf/argon2id/impl/go -run '^$' -bench BenchmarkDerive64KiB -benchmem -benchtime=200ms -count=3 -cpu=1
```

The tests verify the complete initial digest, eight published words after
each of the three passes, and the final tag in the RFC test with secret
and associated data. They also check 32-bit length limits, workspace
rounding and preservation of output and workspace on rejection. Node/OpenSSL compares
110 deterministic inputs, including 1–4 lanes, non-aligned memory,
segments that cross the 128-word address batch boundary, and tag lengths
from 4 to 257 bytes. Go 1.24.9 passed on Windows amd64 and Windows 386.
The copied modules passed the RFC vector in a separate offline consumer.
[RFC 9106 §5.3](https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3)

On Windows amd64 with an Intel Core i7-12700K, the median of three
Go runs with 64 KiB, two passes, one lane and a 32-byte tag was
93.872 µs with zero heap allocations per operation. A separate
Node 24.12.0 and OpenSSL 3.5.4 run with the same parameters had
a median of 805.4 µs across three 1,500-call batches. The Go API reuses
caller-allocated workspace and the Node one-shot call owns its allocation.
These measurements cover this machine and these call interfaces.

The Lean model checks workspace rounding and index bounds. Exact Go
source refinement, compiled leakage and workspace erasure remain open.
[Lean bounds](../../spec/Argon2idBounds.lean)
