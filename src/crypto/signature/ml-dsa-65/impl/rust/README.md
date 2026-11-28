# Pure deterministic ML-DSA-65 in Rust

This standalone Cargo crate exposes the functions in [`src/lib.rs`](src/lib.rs). It delegates the primitive to RustCrypto ml-dsa 0.1.2. The manifest pins direct dependency versions and the lockfile records the resolved closure and checksums.

Use a 32-byte seed, a 1952-byte verification key and a 3309-byte signature. The raw context is optional and admits up to 255 bytes. Signing uses the deterministic FIPS 204 mode.

```sh
cargo +1.92.0 test --locked --release --manifest-path src/crypto/signature/ml-dsa-65/impl/rust/Cargo.toml
```

The test checks a published NIST ACVP signature, wrong-context rejection, deterministic repeated output, fixed signature length and the context boundary.

The scope includes the Windows x64 release run. Full release-source refinement, compiler-level leakage verification and other targets remain open. [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) · [RustCrypto ml-dsa 0.1.2](https://docs.rs/ml-dsa/0.1.2)
