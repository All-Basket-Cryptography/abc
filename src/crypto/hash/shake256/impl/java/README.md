# Java SHAKE256

The native Java profile exposes `hash`, `update`, `reset` and `finish`.
Finalization returns an independent reader at byte offset zero and
keeps the absorber available for more input. The reader can return new
bytes or fill caller-owned storage through `read` and `readInto`.
The same-language Keccak-p[1600,24] core uses domain byte `0x1f`.
[FIPS 202 §6.2](https://csrc.nist.gov/pubs/fips/202/final) · [Shared core](../../../keccak-p1600/impl/java)

The checker uses JDK 17 on the executable path or `--jdk`.

```sh
python -B src/crypto/hash/keccak-p1600/impl/java/check.py --language java --algorithm shake256
```

The isolated consumer tests the JARs and their dependency on the
native Keccak core. It compares 11 one-shot vectors and 2,439 split
traces against Node 24.12.0/OpenSSL 3.5.4, including known-answer and
rate-boundary cases. Every split reads 409 bytes using multiple output
chunk sizes and independent readers. Use `--output` to retain the tested
artifacts and source digests.
[NIST example values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)

Lean checks the complete word-oriented permutation and block-oriented
sponge model. Exact Java source refinement and compiled-target
leakage and performance qualification remain open.
[Lean model](../../../keccak-p1600/spec)
