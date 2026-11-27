# Java SHA3-256

The native Java profile exposes `hash`, `update`, `digest` and `reset`. Digest
snapshots leave the absorber available for further input. The same-language
Keccak-p[1600,24] core uses the 136-byte rate and domain byte `0x06`.
Each digest returns 32 caller-owned bytes.
[FIPS 202 §6.1](https://csrc.nist.gov/pubs/fips/202/final) · [Shared core](../../../keccak-p1600/impl/java)

The checker uses JDK 17 on the executable path or `--jdk`.

```sh
python -B src/crypto/hash/keccak-p1600/impl/java/check.py --language java --algorithm sha3-256
```

The isolated consumer tests the JARs and their dependency on the
native Keccak core. It compares 11 one-shot vectors and 2,439 split
traces against Node 24.12.0/OpenSSL 3.5.4, including known-answer and
rate-boundary cases. The independent JDK SHA3-256 provider also checks
each intermediate digest snapshot. Use `--output` to retain the tested
artifacts and source digests.
[NIST example values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)

Lean checks the complete word-oriented permutation and block-oriented
sponge model. Exact Java source refinement and compiled-target
leakage and performance qualification remain open.
[Lean model](../../../keccak-p1600/spec)
