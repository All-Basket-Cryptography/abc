# ABC C SDK research ABI v1

`abc_abi_version()` returns `0x00010000`, with major in the upper 16 bits and
minor in the lower 16. `abc_status` is `int32_t`. `ABC_OK` is zero. The header
defines the stable failure codes. `abc_sha256_implementation()` returns a
read-only, null-terminated string valid for the lifetime of the library.

The one-shot function accepts a read-only byte buffer and writes exactly 32
bytes to caller-provided storage. Bytes beyond the digest are untouched.
Inputs may be null at length zero. Each nonempty input buffer and each
output buffer must be valid for its stated length or capacity within a single
allocation. Writable output cannot overlap the input or a context. Lengths
above the provider limit of `2^61 - 1` bytes or the platform's maximum contiguous
object size are rejected. The caller retains input and output ownership.

`abc_sha256_new` writes an opaque handle into writable, aligned storage for a
pointer. Destroy it once with `abc_sha256_free`; `abc_sha256_free(NULL)` is a
no-op. Handles must be from the same loaded library instance. The caller must
serialize operations on each context, including `free`. Distinct contexts and
the one-shot function may be used concurrently. A valid handle must be aligned,
live and uniquely owned. Null, misalignment, and too-small output are diagnosed
where the function can check them before access. The caller is responsible for
pointer provenance, actual allocation bounds, liveness, and aliasing.

`abc_sha256_update` extends an open context and a rejected length leaves it
unchanged. `abc_sha256_finalize` closes the context after producing an output.
A short output buffer does not consume the context. `abc_sha256_reset` opens an
empty context, including after finalize. Rust panics that unwind are caught at
status-returning entry points. After `ABC_ERROR_PANIC`, release the affected
context. Aborting panics and process resource failures may terminate the
process. The ABI accepts no callbacks. Rust layout details are private.

From the source checkout:

```sh
python src/crypto/hash/sha256/sdk/c/package.py --sdk c --consumer
python src/crypto/hash/sha256/sdk/c/fuzz.py --runs 10000
```

Extract the C archive to an installation prefix and pass it in
`CMAKE_PREFIX_PATH`. `find_package(ABCCrypto 0.1 CONFIG REQUIRED)` provides
`ABC::c` and `ABC::c_shared`. Windows shared-library consumers must make the DLL
available to the loader. The package emits a symbol baseline checked at build
time and exercises static and shared consumers from freshly extracted archives.
The tested configuration and assurance limits are recorded with execution
evidence in the repository.
