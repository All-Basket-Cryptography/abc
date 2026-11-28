# Native C SHA-256

This implementation builds HACL*'s SHA-256 translation unit from CPython 3.14.2 as a native C library. The small ABC adapter exposes an independent one-shot and streaming API through `abc_sha256_c.h`. The native core has no Rust dependency.

## Build and test

Run from the repository root with Clang, Python with its OpenSSL-backed `_hashlib` module, and a native linker. On Windows, use a Visual Studio developer shell for the target architecture. The checkout includes the complete translation-unit source closure.

```sh
python -B src/crypto/hash/sha256/impl/c/check.py --output .abc/sha256-c-native
```

The checker verifies the vendored source digests, compiles the C library, and exercises it in an external process. Run with `--cc` to select a compatible compiler. Add `--archive` with the pinned CPython tarball to compare every vendored CPython file byte-for-byte. Add `--hacl-source` with the pinned HACL* SHA-2 C file to reproduce the CPython translation unit from the documented transformations. [Source and checksum manifest](upstream/source.json)

The one-shot path uses the upstream direct routine for inputs through `UINT32_MAX` bytes. Larger valid inputs use the streaming routine with 32-bit chunks. The adapter preflights the total byte length before sending any chunk to HACL*. A zero-length update accepts a NULL input. Each other accepted input must have readable storage for its entire length. Caller-provided outputs need 32 writable bytes. One-shot input may overlap output. An update or digest requires a live owned context and external synchronization for concurrent use of that context.

## Source provenance

CPython's `Modules/_hacl/refresh.sh` identifies HACL* revision `8ba599b2f6c9701b3dc961db895b0856a2210f76`. ABC preserves thirteen exact CPython C and header files from revision `df793163d5821791d4e7caf88885a2c11a107986` and the applicable upstream notices. The pinned HACL* `dist/gcc-compatible/Hacl_Hash_SHA2.c` matched CPython's C file after removing the generated `Hacl_Krmllib.h` include and trimming trailing whitespace as the refresh script specifies. The original translation unit also contains the other SHA-2 variants. The ABC shared library exposes the five SHA-256 adapter functions. [CPython refresh](https://github.com/python/cpython/blob/df793163d5821791d4e7caf88885a2c11a107986/Modules/_hacl/refresh.sh) · [HACL* C source](https://github.com/hacl-star/hacl-star/blob/8ba599b2f6c9701b3dc961db895b0856a2210f76/dist/gcc-compatible/Hacl_Hash_SHA2.c)

## Evidence and proof scope

Clang 21.1.8 ran the C check on `x86_64-pc-windows-msvc`. The check compared three known answers, 154 one-shot cases, and 950 intermediate streaming snapshots with OpenSSL 3.0.18. It also exercised NULL handling, cumulative length rejection, preservation of the state and output buffer on validation errors, and overlapping one-shot input and output. The checked archive, compiler commands, and library digest are captured in the generated `result.json`.

The same cases passed with both C objects instrumented at `-O1 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer` and linked with the same sanitizers. The OpenSSL consumer ran against that instrumented DLL. The Windows export table contained the five public adapter functions.

Lean 4.31.0 checked the mathematical byte-domain guard, exact 32-bit chunk conversion, progress, and capacity invariant in `proof/Length.lean`.

```sh
lean src/crypto/hash/sha256/impl/c/proof/Length.lean
```

The upstream proof source is in F*. This integration has source lineage and native functional tests. Full C-source refinement to ABC's Lean SHA-256 specification, compiler and binary correspondence, and secret-dependent leakage evidence remain open. [HACL* SHA-2 specification interface](https://github.com/hacl-star/hacl-star/blob/8ba599b2f6c9701b3dc961db895b0856a2210f76/code/hash/Hacl.Hash.SHA2.fsti) · [Upstream extraction route](https://hacl-star.github.io/Obtaining.html)
