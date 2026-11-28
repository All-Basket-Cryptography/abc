# Portable Go HMAC-SHA-256

This research implementation computes the full 32-byte HMAC tag in Go. It uses
ABC's portable Go SHA-256 for key normalization and both hash states. A key of
up to 64 bytes is zero-padded. A longer key is hashed before padding. The key
limit is `2^61 - 1` bytes and the cumulative message limit is `2^61 - 1 - 64`
bytes. [RFC 2104 § 2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2)
· [ABC specification](../../spec/README.md)

`New` creates a keyed context. `Update` accepts arbitrary byte chunks and
leaves the context unchanged on length rejection. `Digest` returns a snapshot
of the full tag and keeps the context open. `Authenticate` performs all three
steps on one message. The constructor accepts an explicit empty key. The zero
value of `Hasher` reports `ErrUninitialized`. The context retains no caller
buffers. Calls on one context must be serialized.

Run in this module directory with Go 1.24.9 and `CGO_ENABLED=0`.

```sh
go test -count=1 -cover ./...
go vet ./...
go test -run '^$' -fuzz '^FuzzDifferential$' -fuzztime 10000x -parallel 2
```

Go 1.24.9 passed the suite with `CGO_ENABLED=0` on Windows amd64 and 386. The
amd64 run covered 81.0% of statements, passed `go vet`, and completed 10,000
differential fuzz cases with two workers. The suite checks seven RFC 4231
cases and 5,670 two-part traces around padding and key-length boundaries.
It also checks intermediate tag snapshots, caller-buffer ownership, and
atomic rejection by setting the internal admission counter to its limit.
Go's `crypto/hmac` and `crypto/sha256` serve as differential oracles only.
[RFC 4231 § 4](https://www.rfc-editor.org/rfc/rfc4231.html#section-4)

The local module uses a relative dependency on ABC's Go SHA-256 source.
Independent distribution, Go source-to-Lean refinement, and target-specific
leakage and performance evidence remain open.
