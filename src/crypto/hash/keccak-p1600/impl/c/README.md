# C Keccak-p[1600,24]

The portable C11 core applies Keccak-p[1600,24] to 25 unsigned
64-bit lanes in `x + 5*y` order. The C SHA3-256 and SHAKE256 SDKs
share this permutation and a 136-byte sponge. The sponge consumes
bytes before returning. Finalization snapshots the state into an
independent reader. The caller owns all storage.
[FIPS 202 §§3–5](https://csrc.nist.gov/pubs/fips/202/final)

The ρ/π cycle uses fixed lane destinations and rotations.
The scheme uses portable little-endian loads and stores for
absorption and squeezing. The shared Lean model checks the
mathematical lane mapping and round operations. Complete
C source and target refinement remains open.
[Shared round model](../../spec/KeccakRound.lean)

The checker links a native C library and compares the permutation
against the published XKCP zero-state result and 128 independent
FIPS-equation cases. Windows x64 Clang 21.1.8 passed optimized
and UndefinedBehaviorSanitizer builds.
[XKCP intermediate values](https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt)

```sh
python -B src/crypto/hash/keccak-p1600/impl/c/check.py keccak-p1600
python -B src/crypto/hash/keccak-p1600/impl/c/check.py keccak-p1600 --ubsan
```

Use a Visual Studio developer shell on Windows. Applications can link
`abc_keccak_p1600_c.c` directly and include `abc_keccak_p1600_c.h`.
