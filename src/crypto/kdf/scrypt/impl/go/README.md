# Go scrypt

`NewParameters(N, r, p)` checks RFC domain and machine-size bounds for
the work table. `WorkspaceBytes` returns the bytes required for the
input lanes, table and temporary block. `Derive` accepts an explicit
budget for these buffers plus the requested output. It returns an owned
key. The implementation performs Salsa20/8, BlockMix and ROMix in Go,
visits lanes serially, and calls the ABC Go PBKDF2-HMAC-SHA-256 implementation
for the initial and final derivation. [RFC 7914 §§2–7](https://www.rfc-editor.org/rfc/rfc7914.html#section-2)

```sh
go test -C src/crypto/kdf/scrypt/impl/go -count=1 ./...
python -B src/crypto/kdf/scrypt/spec/verify.py --implementation go
```

The tests include RFC known answers and compare 144 independently
computed OpenSSL outputs. The RFC ROMix table is accessed using
data-dependent indexes. Callers set separate deployment bounds on the
work and the output length. The core clears its working byte slices on
return. Compiled-code erasure, timing and complete Go source refinement
remain open. [RFC 7914 §§11–14](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)
