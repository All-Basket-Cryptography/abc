# Go ML-KEM-768

The SDK uses Go 1.24.9's native `crypto/mlkem` implementation for FIPS
203 ML-KEM-768. The exported array sizes fix the public key at 1,184
bytes, ciphertext at 1,088 bytes and shared secret at 32 bytes.
`GenerateKey()` draws from the Go runtime's cryptographic RNG.
`NewDecapsulationKey(seed)` accepts a private, uniformly random
64-byte `d || z` seed. The SDK uses seed-based key storage.
[FIPS 203 §§6–7](https://csrc.nist.gov/pubs/fips/203/final) · [Go 1.24.9 provider](https://github.com/golang/go/blob/go1.24.9/src/crypto/mlkem/mlkem.go)

The provider checks encapsulation-key encoding and ciphertext length.
Decapsulation of a correctly sized invalid ciphertext derives the
implicit-rejection secret. On error the fixed-size output is zero.
The caller supplies protocol authentication and controls key lifetime.
Provider source refinement and runtime leakage or erasure qualification
remain open.
[Go 1.24.9 ML-KEM-768 arithmetic](https://github.com/golang/go/blob/go1.24.9/src/crypto/internal/fips140/mlkem/mlkem768.go)

```sh
go test -C src/crypto/agreement/ml-kem-768/impl/go -count=1 -v ./...
```

Run with Go 1.24.9 and Node 24.12. The tests use two NIST key-generation
vectors and one rejection of a noncanonical encapsulation key, four
random SDK round trips, and 12 cross-provider cases. The OpenSSL 3.5.4
oracle checks public-key derivation, two-way encapsulation and the exact
implicit-rejection key. Seed-based PKCS#8 input uses RFC 9935.
[Pinned NIST subset provenance](../../spec/acvp.json) · [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935.html) · [FIPS 203 potential updates](https://csrc.nist.gov/files/pubs/fips/203/final/docs/fips-203-potential-updates.xlsx)
