# Swift SHA-256 research SDK

`ABCCrypto` wraps the versioned C ABI. `SHA256.digest` accepts bytes and returns
a 32-byte digest. `SHA256Stream` owns its native handle and serializes access.
Finalizing closes the current hash state. `reset()` opens an empty state and
`close()` releases the handle. The package checks the native ABI before use.
The provider is the portable Rust SHA-256 implementation. The current API
does not take keys or require randomness.

On a host with Swift 5.9 or later, pkg-config, and Rust 1.92.0 installed, run:

```sh
python src/crypto/hash/sha256/sdk/swift/package.py --consumer
```

The ZIP contains the Swift package, native archive, C header, and relative
pkg-config metadata. Extract it, add its `native/lib/pkgconfig` directory to
`PKG_CONFIG_PATH`, and use the extracted directory as a SwiftPM dependency.
The included separate consumer verifies the `abc` vector, streaming, reset,
and handle closure from the unpacked archive. The macOS research workflow
passed on Apple silicon. Successful workflow runs retain the tested ZIP and
`swift-artifacts.json` for seven days under `abc-swift-research-macos-arm64`.
iOS simulator, device, and XCFramework verification remain open.
[Hosted consumer evidence](EVIDENCE.md)
