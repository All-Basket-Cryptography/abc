# Go BLAKE2b

This native Go implementation covers sequential, unkeyed BLAKE2b with
digest sizes of 1–64 bytes. `New(size)` fixes the size in the parameter
block, and the zero-value `Hasher` uses 64 bytes. `Update` absorbs
caller-provided bytes with a 128-bit byte counter. `Finalize(output)`
writes a snapshot to a buffer of exactly the configured size. `Reset`
starts another message with that size. `Sum(input, output)` is the
one-shot API, which supports overlapping input and output slices.
[RFC 7693 §§2–3](https://www.rfc-editor.org/rfc/rfc7693.html#section-2)

Every full final block remains pending until the caller appends more
bytes or asks for a snapshot. The digest size changes the initial state,
so each size has its own digest definition. Counter overflow preserves
the absorber, and an output size error preserves the output buffer.

The module uses only the Go standard library. A separate consumer may
require the module and replace it with a pinned copy of this directory.

```sh
go test -C src/crypto/hash/blake2b/impl/go -count=1 ./...
go test -C src/crypto/hash/blake2b/impl/go -run '^$' -bench BenchmarkSum4096 -benchmem -benchtime=200ms -count=3 -cpu=1
```

The suite checks the final digest from the RFC `abc` example and the SHA-256 aggregate of 576
independently generated `hashlib.blake2b` outputs. These span all digest
sizes across lengths 0, 1, 127, 128, 129, 255, 256, 257 and 1,000. The
aggregate orders messages by this list and digest sizes from 1 through 64
within each message. Message byte `i` is `(37*i + 11) mod 256`. The suite
checks 6,486 two-chunk traces at digest sizes 1, 31 and 64 as well as
the 128-bit counter boundary. A separately copied Go consumer compared
each of the 576 outputs directly against CPython 3.13.14.
[RFC 7693 Appendix A](https://www.rfc-editor.org/rfc/rfc7693.html#appendix-A)

The Lean buffer model checks final-block arithmetic. Source-to-model
refinement and target-specific timing assurance remain open.
[Lean buffer model](../../spec/Blake2bBuffer.lean)

The Windows amd64 and 386 tests passed with Go 1.24.9 and cgo disabled.
In a separate consumer on Windows amd64 and Intel Core i7-12700K,
three 200 ms batches with one worker gave median 4,096-byte latencies of
7.276 µs for `Sum` and 3.220 µs for `golang.org/x/crypto/blake2b` v0.37.0
`Sum512`. Both calls reported zero heap allocations.
[Go x/crypto reference](https://pkg.go.dev/golang.org/x/crypto@v0.37.0/blake2b)
