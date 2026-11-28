# ML-KEM-768 in Rust

This standalone Cargo crate exposes the functions in [`src/lib.rs`](src/lib.rs). It delegates the primitive to RustCrypto ml-kem 0.3.4. The manifest pins direct dependency versions and the lockfile records the resolved closure and checksums.

Use a 64-byte d∥z seed, a 1184-byte encapsulation key and a 1088-byte ciphertext. Encapsulation uses fresh provider randomness. A correctly sized altered ciphertext produces a 32-byte implicit-rejection secret.

```sh
cargo +1.92.0 test --locked --release --manifest-path src/crypto/agreement/ml-kem-768/impl/rust/Cargo.toml
```

The test includes the NIST ACVP encoded public key, random round-trip, noncanonical key rejection and the SHAKE256 implicit-rejection value. The adapter obtains randomness from `getrandom` and propagates entropy failure.

The scope includes the Windows x64 release run. Full release-source refinement, compiler-level leakage verification and other targets remain open. [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) · [RustCrypto ml-kem 0.3.4](https://docs.rs/ml-kem/0.3.4)
