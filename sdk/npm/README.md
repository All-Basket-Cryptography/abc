# ABC SHA-256 for JavaScript

Research package with a Rust/WASM SHA-256 provider and TypeScript declarations. Import `createSha256Provider` and await initialization. Pass `Uint8Array` bytes to `provider.digest` or create a streaming context using `provider.create()`. Finalization closes that context. Call `dispose()` when abandoning a context before finalization.

Node loads the adjacent `.wasm` file from the installed package. In a browser, serve the JavaScript and its adjacent WASM file over HTTP and import the JavaScript module. `provider.identity` reports the selected implementation and target.
