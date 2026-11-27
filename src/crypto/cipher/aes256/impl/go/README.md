# AES-256 in Go

`New` expands a 32-byte AES-256 key. The initialized cipher encrypts and
decrypts 16-byte blocks without changing the key schedule. Two 64-bit words
hold the state, with eight independent field elements in each word. Field
multiplication, squaring, row permutation and column mixing use fixed
arithmetic and bit operations. The substitution and expansion code has
no secret-indexed lookup tables at source level. Use the separately
authenticated GCM profile for message encryption.
[FIPS 197, May 2023 update](https://csrc.nist.gov/pubs/fips/197/final)

The two NIST known answers and 512 independent pairs of Go
`crypto/aes` encryption and decryption comparisons pass. A
test-only polynomial implementation checks every byte pair for
multiplication in every packed lane, as well as square and
substitution outputs. Lean 4.31.0 checks the square's scalar
coefficients against field multiplication for all 256 inputs.
Full source refinement, compiled-target leakage and key-lifetime
assurance remain open.
[NIST SP 800-38A, Appendix F.1.5](https://csrc.nist.gov/pubs/sp/800/38/a/final) · [Lean square model](Aes256GoSquare.lean)

On Windows amd64, Go 1.24.9 and an Intel Core i7-12700K, the median of
five block encryption measurements was 2.074 µs for the packed profile
and 10.77 ns for the Go standard provider. Both reuse an expanded
schedule and report zero heap allocations per operation.

```sh
go test -C src/crypto/cipher/aes256/impl/go -count=1 -v ./...
lean src/crypto/cipher/aes256/impl/go/Aes256GoSquare.lean
go test -C src/crypto/cipher/aes256/impl/go -run '^$' -bench '^BenchmarkEncryptBlock$' -benchtime 100ms -count 5
```
