# Native C PBKDF2-HMAC-SHA-256

The `abc_pbkdf2_sha256_c_derive` function uses the repository's native C HMAC-SHA-256 implementation. It uses a four-byte big-endian block index, XORs the HMAC iterates, and copies the requested number of derived bytes. [RFC 8018 §5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2) · [Native C HMAC-SHA-256](../../../../mac/hmac-sha256/impl/c/README.md)

The caller supplies a positive 32-bit iteration count and a writable output buffer of positive length, limited to `32 × (2^32 − 1)` bytes and by platform capacity. Password and salt pointers may be null at length zero. The function stages the full result so errors leave caller output unchanged and valid input and output buffers can overlap. It allocates temporary storage of the requested output size.

## Run conformance

From the repository root, run with Clang and CPython with OpenSSL support. Use `--cc` to choose the compiler.

```sh
python -B src/crypto/kdf/pbkdf2-hmac-sha256/impl/c/check.py --output .abc/c-pbkdf2-conformance
```

Clang 21.1.8 on Windows x64 passed both RFC 7914 vectors and 196 comparisons with OpenSSL 3.0.21. These exercised empty and binary inputs, long passwords, partial and full output blocks, the block index transition from 255 to 256, overlap and output preservation on validation errors. The checker verifies pinned HACL* source digests and records compiler commands and the library digest in `result.json`. [RFC 7914 §11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)

The same tests passed with all four C source files built at `-O1 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer`. The checker accepts `--exercise <library>` to test an existing build.

This research implementation has native functional evidence. Exact source refinement, leakage analysis and key erasure remain open.
