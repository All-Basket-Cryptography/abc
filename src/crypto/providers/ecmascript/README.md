# ECMAScript crypto providers

Use Node 24.12.0 for the recorded run. Install the pinned Noble dependencies from the repository root.

```sh
npm ci --ignore-scripts --no-audit --prefix src/crypto/providers/ecmascript
```

The lockfile records the exact dependency closure. Native operations use the OpenSSL bundled with the selected Node runtime. The verified Windows x64 build reports OpenSSL 3.5.4. Native Argon2id and Curve25519 are Node APIs. The JavaScript and TypeScript SDKs contain separate entry code and share the same upstream provider boundary.

The base environment for Argon2id differential tests includes the pinned Rust 1.92.0 toolchain and the portable Argon2id Cargo workspace dependencies. Each profile README lists its test command. [Node 24.12.0 crypto](https://nodejs.org/download/release/v24.12.0/docs/api/crypto.html) · [Noble curves](https://github.com/paulmillr/noble-curves) · [Noble post-quantum](https://github.com/paulmillr/noble-post-quantum)
