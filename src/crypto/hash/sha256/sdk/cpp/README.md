# ABC C++ SDK research package

The C++17 facade owns the C ABI v1 context through RAII. `abc::sha256_stream`
is movable and has no copy operation. Moving transfers ownership. Accessing a
moved-from stream throws `abc::error` with `ABC_ERROR_STATE`. `finalize()`
returns a fixed-size byte array and closes the stream. `reset()` reopens an
empty context. ABI failures become `abc::error` with the original status code.
The caller retains input buffers and must meet the C ABI's pointer and thread
requirements.

```sh
python src/crypto/hash/sha256/sdk/c/package.py --sdk cpp --consumer
```

Install the matching C and C++ archives at the same CMake prefix and use
`find_package(ABCCryptoCpp 0.1 CONFIG REQUIRED)` with `ABC::cpp`. The C package
supplies the native libraries. The C++ link interface uses the static C target.
