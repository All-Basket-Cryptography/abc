# Swift BLAKE2b

Add the `AbcBlake2bSwift` package and import its library. Its Swift
core implements sequential, unkeyed BLAKE2b with 1–64-byte digests.
The parameter block binds the digest size. The 128-bit count tracks
message bytes, and a complete last block stays pending for finalization.
[RFC 7693 §§2–3](https://www.rfc-editor.org/rfc/rfc7693.html#section-2)

Use `Blake2b(digestSize:)` to create a stream. `update` absorbs an array
or array slice, and `digest()` returns a snapshot. `reset()` clears the
stream at the same size. `Blake2b.hash(_:digestSize:)` hashes a complete
byte array. The default size is 64 bytes. Invalid sizes and counter
overflow raise `Blake2bError`. Overflow leaves the stream unchanged.

The native XCTest always checks the RFC known answer, copy independence,
size validation and counter boundaries. The optional fixture file adds
four project known answers, 139 OpenSSL comparisons, 697 CPython
`hashlib.blake2b` comparisons, 841 prefix snapshots and 4,926 two-chunk
splits. The macOS workflow uses that corpus in a warnings-as-errors
Release build. Lean checks final-block retention in the independent
buffer model. Swift source refinement, compiled-target timing analysis
and performance measurements remain open.
[RFC 7693 Appendix A](https://www.rfc-editor.org/rfc/rfc7693.html#appendix-A) · [BLAKE2 project known answers](https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json) · [Lean buffer model](../../spec/Blake2bBuffer.lean) · [BLAKE2 design paper](https://www.blake2.net/blake2_lncs.pdf)

```sh
export ABC_BLAKE2B_FIXTURES="${TMPDIR:-/tmp}/abc-blake2b-fixtures.txt"
python -B src/crypto/hash/blake2b/impl/swift/make_fixtures.py "$ABC_BLAKE2B_FIXTURES"
swift test --package-path src/crypto/hash/blake2b/impl/swift/AbcBlake2bSwift --configuration release -Xswiftc -warnings-as-errors
```
