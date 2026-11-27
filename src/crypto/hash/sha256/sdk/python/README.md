# Python research wheel

The `abc-crypto-research` wheel exposes byte-oriented SHA-256 through a
PyO3 0.23.5 extension built directly against the portable Rust core.
The package includes the native extension and loads it from the installed
module directory. The local package name is a candidate.

Build the wheel and source distribution and exercise each in a clean offline virtual environment
using 64-bit CPython 3.13 on Windows, Rust 1.92.0, and the MSVC linker.

Prime the Cargo cache with the versions pinned in the native crate lockfile.

```powershell
cargo +1.92.0 fetch --locked --manifest-path src/crypto/hash/sha256/sdk/python/native/Cargo.toml
```

```powershell
python src/crypto/hash/sha256/sdk/python/wheel.py --output .abc/dist/python --sdist --consumer-test
```

The installed consumer can use a single call or stream multiple byte buffers.

```python
from abc_crypto import Sha256, sha256

assert len(sha256(b"abc")) == 32

with Sha256() as digest:
    digest.update(b"a")
    digest.update(memoryview(b"bc"))
    assert digest.finalize() == sha256(b"abc")
```

Buffers must hold single-byte items. The binding copies mutable and strided
input into owned bytes for each call and returns an immutable digest.
Finalization requires `reset()` before the next message. The context manager
releases the native state, and `close()` is idempotent. Invalid lifecycle
operations raise `ValueError`. A native input length overflow raises
`OverflowError`.

The wheel targets only the demonstrated CPython 3.13 and Windows x86-64
combination. Source installs build the PyO3 extension with the same locked
Rust toolchain and require the MSVC linker. The source archive contains the
locked Cargo dependency sources for offline builds. Both distributions
include the locked dependency license texts. Other Python versions and
platforms are pending. This package carries research-level
functional test evidence for the binding and bundled library.
