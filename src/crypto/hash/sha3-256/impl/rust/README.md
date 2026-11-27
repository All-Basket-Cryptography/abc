# SHA3-256 research control

`abc-sha3-256` exposes `digest(&[u8]) -> [u8; 32]` for byte-aligned messages. It
uses the 136-byte rate, Keccak-p[1600, 24], and the SHA-3 domain separator.
The domain separator gives SHA3-256 different digests from legacy Keccak-256.
[FIPS 202, sections 3 through 6](https://csrc.nist.gov/pubs/fips/202/final)

The implementation uses `no_std`, safe Rust, and a local scalar permutation. It
serves as a research control for incremental verification. Functional refinement,
side-channel assurance, and production approval are pending.

```sh
cargo test --locked -p abc-sha3-256
```

Known answers include the NIST 0-bit and 1600-bit examples. Boundary vectors were
calculated with Python `hashlib.sha3_256` backed by OpenSSL 3.0.21, using byte
`i % 251` at each input position `i`. [NIST empty-message example](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg0.pdf)
[NIST 1600-bit example](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_1600.pdf)
