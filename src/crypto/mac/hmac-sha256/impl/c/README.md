# Native C HMAC-SHA-256

The native C API provides one-shot authentication and a streaming context with repeatable digest snapshots. It implements HMAC using the repository's pinned HACL* C SHA-256 implementation. [RFC 2104 §2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2) · [Native C SHA-256 source and provenance](../../../../hash/sha256/impl/c/README.md)

Use `abc_hmac_sha256_c.h` with the C SHA-256 adapter include path. A new context consumes the key before returning and owns its internal state until freed. Callers serialize operations on a shared context. A null key or input is accepted at length zero. The output must have at least 32 writable bytes. Authentication permits overlapping input and output. Validation errors preserve an existing context and leave the output unchanged.

## Run conformance

From the repository root, run this command with Clang and CPython with OpenSSL support. Use `--cc` to specify a compiler path.

```sh
python -B src/crypto/mac/hmac-sha256/impl/c/check.py --output .abc/c-hmac-conformance
```

Clang 21.1.8 on Windows x64 passed two RFC 4231 vectors and 77 independent OpenSSL 3.0.21 comparisons with two streaming snapshots per case. The same run tested key storage ownership, length limits, null arguments, overlapping buffers and unchanged output on failure. The checker verifies the pinned SHA-256 source closure and records compiler commands and the library digest in `result.json`. [RFC 4231 §4](https://www.rfc-editor.org/rfc/rfc4231.html#section-4)

The same tests passed on a Windows DLL that instrumented HMAC, the SHA-256 adapter and the HACL* source at `-O1 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer`. The checker accepts `--exercise <library>` to test an existing build.

This research implementation has native functional evidence. Exact C source refinement, compiler and binary correspondence, leakage and key erasure remain open.
