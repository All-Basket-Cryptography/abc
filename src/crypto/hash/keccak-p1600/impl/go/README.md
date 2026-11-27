# Go Keccak-p[1600,24]

The shared portable Go core implements all 24 rounds and a 136-byte sponge for
SHA3-256 and SHAKE256. `Permute` updates 25 unsigned 64-bit lanes in `x + 5*y`
order. The implementation uses fixed round constants, rotations and lane
indices. Sponge blocks are little-endian and the domain-specific finalizer
sets the final padding bit in the last rate byte. The state and tail use
fixed-size arrays.
[FIPS 202 §§3–4 and §6](https://csrc.nist.gov/pubs/fips/202/final)

Run the permutation test from the repository root with Go 1.24.9.

```sh
go test -C src/crypto/hash/keccak-p1600/impl/go -count=1 ./...
```

The permutation test compares all 25 lanes with the first XKCP output for the
zero state. The dependents perform independent checks with Go's standard
library. Lean checks the word-oriented round and sponge model against
individual bit equations. Source refinement and compiled leakage evidence
remain open.
[XKCP permutation vectors](https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt) · [Lean model](../../spec)
