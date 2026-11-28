# AES-256-GCM in Go

This native module composes the ABC Go AES-256 core, a counter stream
and a fixed-iteration GHASH multiplier. It fixes the nonce to 96 bits
and the detached authentication tag to 128 bits. `New` expands the
key and derives the GHASH key once. Supply a distinct nonce for every
encryption under the same key.
[NIST SP 800-38D §§5–8](https://csrc.nist.gov/pubs/sp/800/38/d/final)

`SealDetached` writes ciphertext to the equally long destination
prefix. `OpenDetached` verifies the entire tag before writing
plaintext. Either operation accepts overlapping buffers, including
associated data, and preserves the destination on rejection. The
profile limits payloads to `(2^32 - 2) * 16` bytes and associated data
to `floor((2^64 - 1) / 8)` bytes.

The NIST examples and 400 bidirectional comparisons against the
standard Go AES and GCM passed. Tests also cover length boundaries,
overlap and preservation on rejected tag bytes, altered ciphertext
and altered associated data. The repository's independent GCM model
checks counter bounds and the tag comparison equality. Complete
correspondence with the Go source and the compiled platform requires
further evidence.
[NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf) · [Lean GCM bounds](../../spec/Aes256GcmBounds.lean)

On Windows amd64 with Go 1.24.9 and an Intel Core i7-12700K, five
trials yielded the following medians. Both profiles reuse a key,
use a distinct nonce in each batch and report zero allocations.
The standard API appends the tag while this profile returns it
separately.

| Payload | This Go profile | Go standard provider |
| --- | ---: | ---: |
| 64 bytes | 11.369 µs | 81.07 ns |
| 4 KiB | 553.131 µs | 593.2 ns |

```sh
go test -C src/crypto/aead/aes256-gcm/impl/go -count=1 -v ./...
go test -C src/crypto/aead/aes256-gcm/impl/go -run '^$' -bench '^BenchmarkSeal$' -benchtime 100ms -count 5
```

An application using a local checkout maps the GCM and AES-256 module
paths to their corresponding `impl/go` directories in its own
`go.mod`.
