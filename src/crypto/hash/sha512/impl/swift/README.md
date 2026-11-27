# Swift SHA-512

The `AbcSha512Swift` package implements byte-oriented FIPS 180-4
SHA-512 in Swift. The digest is a 64-byte snapshot of a stream. Copies
of a stream can be updated independently. The byte count uses two
`UInt64` words and the bit-length field is 128 bits.
[FIPS 180-4 §§4–6](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

```sh
swift test --package-path src/crypto/hash/sha512/impl/swift/AbcSha512Swift --configuration release -Xswiftc -warnings-as-errors
```

The suite uses CryptoKit as an independent oracle and includes known
answers, all splits around block and padding boundaries, and snapshot
ownership. The direct Swift source and runtime refinement remain open.
[Lean schedule model](../../spec/Sha512Ring.lean)

Apple Swift 6.1.2 passed the Release suite on macOS arm64 with three
known answers, 14 independent CryptoKit comparisons and 9,021 streaming
snapshots. [Hosted run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46079389105/job/140774570482)
