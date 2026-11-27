# Python research wheel

The `abc-crypto-research` wheel exposes byte-oriented SHA-256 through the
versioned ABC C ABI. It includes a Windows native library and loads it
from the installed module directory. The local package name is a candidate.

Build the wheel and source distribution and exercise each in a clean offline virtual environment
using 64-bit CPython 3.13 on Windows, Rust 1.92.0, and the MSVC linker.

```powershell
python sdk/python/wheel.py --output .abc/dist/python --sdist --consumer-test
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
combination. Source installs build the bundled C ABI with the same locked
Rust toolchain and require the MSVC linker. Other Python versions and
platforms and PyO3 integration are pending. This package carries research-level
functional test evidence for the binding and bundled library.
