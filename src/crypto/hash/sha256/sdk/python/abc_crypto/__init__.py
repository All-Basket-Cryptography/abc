"""Research SHA-256 bindings for the ABC portable core."""

from collections.abc import Buffer
from threading import Lock

from . import _native

__all__ = ["ABI_VERSION", "IMPLEMENTATION_ID", "Sha256", "sha256"]

_ABI_VERSION_1 = 0x00010000
ABI_VERSION = _native.ABI_VERSION
IMPLEMENTATION_ID = _native.IMPLEMENTATION_ID
if ABI_VERSION != _ABI_VERSION_1:
    raise ImportError(f"ABC ABI {ABI_VERSION:#x} is incompatible with expected ABI {_ABI_VERSION_1:#x}")


def _byte_string(data: Buffer) -> bytes:
    if type(data) is bytes:
        return data
    with memoryview(data) as view:
        if view.itemsize != 1:
            raise TypeError("ABC SHA-256 requires a buffer of single-byte items")
        return view.tobytes()


def sha256(data: Buffer) -> bytes:
    """Return the 32-byte digest of a byte-oriented buffer."""
    return _native.sha256(_byte_string(data))


class Sha256:
    """Own an ABC SHA-256 state and serialize native calls on that state."""

    __slots__ = ("_lock", "_context", "__weakref__")

    def __init__(self) -> None:
        self._lock = Lock()
        self._context = _native.Context()

    def __copy__(self):
        raise TypeError("SHA-256 context ownership cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("SHA-256 context ownership cannot be copied")

    def _open_context(self):
        if self._context is None:
            raise ValueError("The SHA-256 context is closed")
        return self._context

    def update(self, data: Buffer) -> None:
        """Add bytes to the current message."""
        payload = _byte_string(data)
        with self._lock:
            self._open_context().update(payload)

    def finalize(self) -> bytes:
        """Return the digest and require reset before accepting more input."""
        with self._lock:
            return self._open_context().finalize()

    def reset(self) -> None:
        """Reset an open context for a new message."""
        with self._lock:
            self._open_context().reset()

    def close(self) -> None:
        """Release the native context. Repeating this call is safe."""
        with self._lock:
            self._context = None

    def __enter__(self) -> "Sha256":
        with self._lock:
            self._open_context()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
