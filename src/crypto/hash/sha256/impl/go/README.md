# Portable Go SHA-256

ABC's independent research implementation uses Go word arithmetic and byte
encoding. It implements the padding, schedule, compression, and digest encoding
of FIPS 180-4 directly. `crypto/sha256` is used only by the tests as a separate
oracle. The implementation has no third-party module dependencies or native
library calls. [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

`Sum256` hashes one byte slice. A `Hasher` accepts successive `Update` calls, and
`Digest` returns the current digest while keeping the context open. `Reset`
starts a fresh message. The zero value is usable. Updates beyond the 64-bit
bit-length domain return `ErrMessageTooLong` before any state changes.

## Test evidence

Go 1.24.9 passed the suite on Windows amd64 and Windows 386. On Windows amd64,
`go vet` passed, statement coverage reached 98.4%, and a differential fuzz run
completed 10,000 cases using two workers. The suite checks four fixed digests,
1,945 two-chunk splits around padding and block boundaries, 512 deterministic
binary messages against Go's standard implementation, snapshot and reset
behavior, caller-buffer ownership, and the length-limit rejection path. The
limit test sets the internal counter directly.
[NIST worked examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf)
[RFC 6234 test vectors](https://www.rfc-editor.org/rfc/rfc6234.html#section-8.5)

Run from this module directory with Go 1.24.9 and `CGO_ENABLED=0`.

```sh
go test -count=1 -cover ./...
go vet ./...
go test -run '^$' -fuzz '^FuzzDifferential$' -fuzztime 10000x -parallel 2
```

The module is standalone research code. A checked correspondence from this Go
source to ABC's SHA-256 specification, qualified performance evidence, and any
SDK routing or release approval remain open.
## Public-input performance

Use `go test -C src/crypto/hash/sha256/impl/go -run '^$' -bench '^BenchmarkSHA256$' -benchtime=250ms -count=3 -cpu=1`. On Windows amd64 with Go 1.24.9 and one runner thread on an Intel Core i7-12700K, the median of three runs was 400 ns per 64-byte digest and 12.64 µs per 4096-byte digest. Go's standard implementation measured 90.5 ns and 1.86 µs under the same command. This portable core is approximately 4.4× and 6.8× slower for those two inputs. The comparison uses public data on one host.
