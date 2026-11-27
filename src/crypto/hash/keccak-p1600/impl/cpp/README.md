# C++ Keccak-p[1600,24]

The portable C++17 core applies Keccak-p[1600,24] to 25 unsigned
64-bit lanes in `x + 5*y` order. The SHA3-256 and SHAKE256 consumers
share this permutation and a 136-byte sponge. The common sponge
reads and writes lanes in little-endian byte order. A reader owns a
snapshot of the finalized state and never allocates memory.
[FIPS 202 §§3–5](https://csrc.nist.gov/pubs/fips/202/final)

The compiler expands the 24-lane ρ/π cycle so each rotation and
destination is constant. Lean checks the cycle's distinct nonzero lanes,
return to its origin, FIPS offsets, and all 24 ι constants against the
specified LFSR. The theorem covers the table model. End-to-end C++ and
compiled-code refinement remain open.
[Shared round model](../../spec/KeccakRound.lean) · [C++ table model](proof/KeccakCppTables.lean)

The checker builds the object separately from its consumer. Clang 21.1.8
on Windows x64 matched the XKCP zero-state example and an independent
FIPS 202 equation-and-LFSR oracle for 128 additional full states. The
same cases passed with UndefinedBehaviorSanitizer.
[XKCP intermediate values](https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt)

```sh
python -B src/crypto/hash/keccak-p1600/impl/cpp/check.py keccak-p1600
python -B src/crypto/hash/keccak-p1600/impl/cpp/check.py keccak-p1600 --ubsan
lean -DwarningAsError=true src/crypto/hash/keccak-p1600/impl/cpp/proof/KeccakCppTables.lean
```

Use a Visual Studio developer environment on Windows.
