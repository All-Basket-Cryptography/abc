# Swift SHAKE256

`AbcShake256Swift` implements SHAKE256 using the same-language Keccak
permutation. `Shake256.update` absorbs byte arrays. `finalize` creates
an independent output reader and leaves the absorption context open.
The reader can write into a reusable byte array using `read(into:)`
or return an array using `read(_ count:)`. `Shake256.xof` is the one-shot
operation. Negative output counts throw before any bytes are consumed.
The profile uses the FIPS delimiter `0x1f`, pad10*1 and a 136-byte rate.
[FIPS 202 §§5 and 6.2](https://csrc.nist.gov/pubs/fips/202/final) · [Swift Keccak core](../../../keccak-p1600/impl/swift/README.md)

The release-mode suite contains three known answers, 59 independent
OpenSSL comparisons through CPython and 3,952 split checks across both
input and output rate boundaries. It includes the empty and 1,600-bit
NIST examples, output up to 4,097 bytes and rejection that preserves
the read position. Complete Swift source and target refinement remains
open.
[NIST empty sample](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf) · [NIST 1,600-bit sample](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg1600.pdf) · [Encoding model](../../spec/Shake256Encoding.lean)

```sh
python3 -B src/crypto/hash/keccak-p1600/impl/swift/make_fixtures.py shake256 --check
swift test --package-path src/crypto/hash/shake256/impl/swift/AbcShake256Swift --configuration release -Xswiftc -warnings-as-errors
```

The macOS workflow targets Apple Swift 6.1.2 on arm64 through Xcode 16.4.
