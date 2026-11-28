# Swift SHA3-256

The standalone `AbcSha3256Swift` package implements byte-oriented
SHA3-256 using the same-language `AbcKeccakP1600Swift` permutation.
`Sha3256.update` absorbs byte arrays and `digest` creates a
non-destructive 32-byte snapshot. `reset` starts a fresh context.
`Sha3256.hash` provides a one-shot operation. The profile uses the
FIPS delimiter `0x06`, pad10*1, and a 136-byte rate.
[FIPS 202 §§5 and 6.1](https://csrc.nist.gov/pubs/fips/202/final) · [Swift Keccak core](../../../keccak-p1600/impl/swift/README.md)

The release-mode suite contains three known answers, 41 independent
OpenSSL comparisons through CPython and 2,145 two-way input splits.
It checks copy-on-write snapshots, reset and caller-buffer reuse.
Published samples include the empty and 1,600-bit NIST messages.
The mathematical encoding model is separate from Swift source
refinement, which remains open.
[NIST empty sample](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg0.pdf) · [NIST 1,600-bit sample](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg1600.pdf) · [Encoding model](../../spec/Sha3Encoding.lean)

```sh
python3 -B src/crypto/hash/keccak-p1600/impl/swift/make_fixtures.py sha3-256 --check
swift test --package-path src/crypto/hash/sha3-256/impl/swift/AbcSha3256Swift --configuration release -Xswiftc -warnings-as-errors
```

The macOS workflow targets Apple Swift 6.1.2 on arm64 through Xcode 16.4.
