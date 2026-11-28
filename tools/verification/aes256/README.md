# Portable Rust AES-256 field and MixColumns verification

Charon extracts the locked portable AES-256 crate. The translator emits Lean
from the `mul_x`, `square` and `mix_column` LLBC bodies. It checks fixed-width
operation types, constant shift bounds, byte casts and the four column reads
and final array write. The trusted library operations are standard unsigned
wrapping subtraction, byte widening and fixed-array indexing.

Lean proves that the extracted multiplication by `x` matches the AES field
reduction for all 256 bytes. It proves that the extracted square equals field
multiplication by the same byte. The MixColumns theorem compares all four
output bytes with the FIPS matrix for arbitrary input bytes. Its proof uses
linearity and XOR identities. [FIPS 197, Sections 4.2 and 5.1.3](https://csrc.nist.gov/pubs/fips/197/final)

```sh
python -B tools/verification/aes256/check.py --check-mutants
cargo +1.92.0 test --release --locked --offline --manifest-path tools/build/rust/Cargo.toml -p abc-aes256
```

The runner checks toolchain pins, requires two independently generated Lean
models to agree, audits the theorem axioms and writes a source digest receipt.
The negative controls change the reduction constant, the square's spread
mask and the order of the first two output bytes in a MixColumns column.
The checked target is Windows x64 MSVC. [Replay receipt](source-receipt-windows-x64.json)

The S-box source, key schedule, encryption and decryption round loops,
compiler-level timing and erasure require separate proof work.
