# ABC WASI SHA-256 command

The research command streams bytes from stdin and prints the 32-byte digest as lowercase hexadecimal. `--identity` reports the exact portable Rust core used in the component. The command requires stdin and stdout capabilities. Hashing needs no filesystem preopens or network capabilities.

Build for WASI Preview 2 with Rust 1.92.0 and check the packaged component using Wasmtime v50.0.3:

```text
rustup target add --toolchain 1.92.0 wasm32-wasip2
python src/crypto/hash/sha256/sdk/wasi/package.py --wasmtime /path/to/wasmtime --output dist/wasi
```

The verifier runs the WASM component with empty input, the NIST `abc` vector, padding boundaries, and input spanning multiple reads. The native unit test exercises the shared streaming adapter. [Rust target](https://doc.rust-lang.org/rustc/platform-support/wasm32-wasip2.html) · [Wasmtime release](https://github.com/bytecodealliance/wasmtime/releases/tag/v50.0.3)
