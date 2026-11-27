# Native C and C++ research SDK evidence

The Windows x64 MSVC ABI packages were built with Rust 1.92.0 and linked in
separate CMake 3.31.6 projects using Clang 21.1.8 and Ninja. The C package
includes a static library, a DLL and import library, the ABI v1 header, and
CMake configuration. The C++ package supplies a C++17 header and CMake target
that link to the C package.

| Archive | SHA-256 | External consumer result |
| --- | --- | --- |
| `abc-c-0.1.0-x86_64-pc-windows-msvc.zip` | `526f33dce11907294cbb5200de52512245cff0e081742ed60afdb4e77ed2dad9` | Static and shared C builds passed. |
| `abc-cpp-0.1.0-x86_64-pc-windows-msvc.zip` | `f07f3e35eb37265d2287b750a6b14e71cd7bf370460014cfe5406f04b12a1588` | The C++17 consumer passed when installed with the C archive above. |

The DLL matched the checked-in eight-symbol ABI baseline. The consumer tests
checked the SHA-256 digest of `abc`, split updates, short-buffer recovery,
reset and finalization, and null handling through the C API. The C++ consumer
also exercised move construction and assignment, copy restrictions, and typed
exception translation. The local run covers Windows x64. The Linux x86-64
packaging path remains unverified on this host.

```sh
python sdk/c/package.py --sdk cpp --consumer --output dist/native
python sdk/c/fuzz.py --runs 10000
```

The native `libfuzzer-sys` 0.4.13 run completed 10,000 generated inputs with
seed `83`, four initial corpus entries, a configured input limit of 1025
bytes, and 29 MiB peak RSS. The harness uses allocated inputs and output
storage, varies split points and capacity, checks lifecycle errors and guard
bytes, and compares FFI output against the same Rust core's one-shot API.
This run used uninstrumented Rust and no sanitizer. The Windows nightly
coverage build hit unresolved sanitizer-coverage runtime symbols when linking
the DLL. Linux coverage and platform-specific ABI verification remain open.
