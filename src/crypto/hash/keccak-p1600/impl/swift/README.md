# Swift Keccak-p[1600,24]

`AbcKeccakP1600Swift` implements the 24-round, 25-lane FIPS 202
permutation in Swift. The public `KeccakP1600.permute` accepts a mutable
array of exactly 25 lanes in `x + 5*y` order. `Sponge136` and
`SpongeReader` share the 136-byte rate for SHA3-256 and SHAKE256.
The sponge consumes input before return and the reader owns a snapshot.
[FIPS 202 §§3–5](https://csrc.nist.gov/pubs/fips/202/final)

The XCTest fixture contains the XKCP zero-state known answer and 16
additional full-state checks derived using independent FIPS equations.
The optional regeneration check validates the fixture against that
oracle. Swift source refinement and compiled-target qualification remain
open. [XKCP zero-state example](https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt) · [Shared mathematical round model](../../spec/KeccakRound.lean)

```sh
python3 -B src/crypto/hash/keccak-p1600/impl/swift/make_fixtures.py keccak-p1600 --check
swift test --package-path src/crypto/hash/keccak-p1600/impl/swift/AbcKeccakP1600Swift --configuration release -Xswiftc -warnings-as-errors
```

The macOS workflow targets Apple Swift 6.1.2 on arm64 through Xcode 16.4.
