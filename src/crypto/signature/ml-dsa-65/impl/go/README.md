# Go Pure deterministic ML-DSA-65

The native research SDK uses the Go 1.27.4 standard-library
`crypto/mldsa` implementation with the ML-DSA-65 parameter set.
`PublicKey` derives a 1,952-byte public key from a 32-byte seed.
`Sign` emits a 3,309-byte deterministic signature over the input
message and its optional binary context. `Verify` checks the exact
public-key and signature lengths, and all calls using a context
enforce its 255-byte limit. The caller supplies and manages key
entropy and seed storage.
[FIPS 204 §§4–6](https://csrc.nist.gov/pubs/fips/204/final)

Signing uses Go's `SignDeterministic` with `mldsa.Options` to select
Pure ML-DSA. The provider hashes `tr || 00 || len(ctx) || ctx || msg`
and uses 32 zero bytes for per-message randomness. Its signing
rejection loop has no explicit attempt limit, and it encodes mask
counters with the standard two bytes. Full termination, source
refinement, compiled-target leakage, and key erasure across the call
chain remain open.
[Pinned Go signing path](https://github.com/golang/go/blob/go1.27.4/src/crypto/internal/fips140/mldsa/mldsa.go#L326-L516) · [FIPS 204 potential updates](https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx)

| Provider source within Go 1.27.4 | SHA-256 in the tested archive |
| --- | --- |
| `src/crypto/mldsa/mldsa.go` | `c0f6aae4badf56c24af4060de43523053d3e7bb842c72f84fdd14350ed1c7925` |
| `src/crypto/mldsa/mldsa_fips140v1.26.go` | `f2faecbe66a9bac604e6636be9cb9578f8a23f2153df9f56babebfe5e1fdd09d` |
| `src/crypto/internal/fips140/mldsa/mldsa.go` | `86a276d8d4f866b45e244d6e5bb3c75ad9b5f27e24e11b2fb3d86bd051d31f80` |

## Reproduction

Use Go 1.27.4 and select Go Cryptographic Module 1.26 or later when
setting `GOFIPS140`. The module builds with `CGO_ENABLED=0` and the
standard library. The interoperability check uses OpenSSL 3.5.4 from
PATH or `ABC_MLDSA_OPENSSL`.

```sh
go test -C src/crypto/signature/ml-dsa-65/impl/go -count=1 -v ./...
go test -C src/crypto/signature/ml-dsa-65/impl/go -count=1 -tags interop -run '^TestOpenSSLInterop$' -v ./...
go test -C src/crypto/signature/ml-dsa-65/impl/go -run '^$' -bench '^BenchmarkSDK$' -benchmem -benchtime=300ms -count=3 ./...
```

On Windows amd64 and 386, the pinned NIST fixture checks key generation group 2 case 26, verifies
the published signature from sigGen group 3 case 41, and checks the
positive and negative sigVer group 3 cases 43 and 38. Case 41 supplies
an expanded private key, so the public seed API uses it as a verification
case. The separate signing oracle derives the same key from the
NIST keyGen seed. Go and OpenSSL matched all 12 deterministic signatures
byte for byte, including binary and 255-byte contexts, then verified
in both directions. Go tests also cover empty messages and malformed
lengths.
[Pinned NIST ACVP keys](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-keyGen-FIPS204) · [Pinned NIST ACVP signing](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigGen-FIPS204) · [Pinned NIST ACVP verification](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204) · [RFC 9881 seed encoding](https://www.rfc-editor.org/rfc/rfc9881.html)

The Go 1.27.4 upstream ML-DSA tests passed on Windows amd64, including
the Wycheproof suites at `ee7b4f7e611928cbe163dc6f5e54527bfd166f34`.
[Pinned Wycheproof vectors](https://github.com/C2SP/wycheproof/tree/ee7b4f7e611928cbe163dc6f5e54527bfd166f34/testvectors_v1)

On Windows amd64 and a Core i7-12700K, the median SDK times were 192 µs
for public key derivation, 441 µs for signing 128 bytes, and 145 µs for
verifying 128 bytes. Signing includes deriving the key from the seed.
Verification includes parsing the public key. These measurements apply
to the listed host and API.
