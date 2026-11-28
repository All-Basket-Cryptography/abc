# Native C HKDF-SHA-256

The native C API exposes extract, expand and derive in `abc_hkdf_sha256_c.h`. It streams each RFC 5869 HMAC input through the repository's native C HMAC-SHA-256 implementation, then copies the requested prefix of the expansion into the caller's output. [RFC 5869 §2](https://www.rfc-editor.org/rfc/rfc5869.html#section-2) · [Native C HMAC-SHA-256](../../../../mac/hmac-sha256/impl/c/README.md)

An omitted salt uses 32 zero bytes. Extract writes 32 bytes and accepts a larger capacity. Expand requires at least 32 PRK bytes, encodes counters from 1 through 255 in one byte each, and accepts output lengths through 8,160 bytes. Null salt, IKM, info and expand or derive output are accepted at zero length. Caller output may overlap valid inputs. An error leaves output unchanged, including when a later expansion block fails.

## Run conformance

From the repository root, run with Clang and CPython with OpenSSL support. Use `--cc` to specify a compiler path.

```sh
python -B src/crypto/kdf/hkdf-sha256/impl/c/check.py --output .abc/c-hkdf-conformance
```

Clang 21.1.8 on Windows x64 passed all three RFC 5869 SHA-256 test cases, 44 expansion comparisons and 36 extract-and-derive pairs against OpenSSL 3.0.21 HMAC. The tests exercised the last allowable counter, partial blocks, zero output, null handling, overlap, length errors and unchanged output on failure. The checker verifies the pinned SHA-256 source closure and records compiler commands and the library digest in `result.json`. [RFC 5869 Appendix A](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)

The same tests passed on a Windows DLL that instrumented all four C sources at `-O1 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer`. The checker accepts `--exercise <library>` to test an existing build.

This research implementation has native functional evidence. Exact C source refinement, compiler and binary correspondence, leakage and key erasure remain open.
