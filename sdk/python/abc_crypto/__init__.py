"""Research SHA-256 bindings for the ABC C ABI."""

from collections.abc import Buffer
from ctypes import CDLL, POINTER, byref, c_char_p, c_int32, c_size_t, c_uint8, c_uint32, c_void_p
from pathlib import Path
from threading import Lock
from weakref import finalize

__all__ = ["ABI_VERSION", "IMPLEMENTATION_ID", "Sha256", "sha256"]

_ABI_VERSION_1 = 0x00010000
_DIGEST_BYTES = 32
_SHA256_OUTPUT = c_uint8 * _DIGEST_BYTES
_library_path = Path(__file__).resolve().with_name("abc_crypto.dll")
try:
    _native = CDLL(str(_library_path))
except OSError as error:
    raise ImportError(f"Unable to load the ABC research wheel library at {_library_path}") from error

_native.abc_abi_version.argtypes = []
_native.abc_abi_version.restype = c_uint32
ABI_VERSION = _native.abc_abi_version()
if ABI_VERSION != _ABI_VERSION_1:
    raise ImportError(f"ABC ABI {ABI_VERSION:#x} is incompatible with expected ABI {_ABI_VERSION_1:#x}")

_native.abc_sha256_implementation.argtypes = []
_native.abc_sha256_implementation.restype = c_char_p
IMPLEMENTATION_ID = _native.abc_sha256_implementation().decode("ascii")
_native.abc_sha256_digest.argtypes = [c_char_p, c_size_t, POINTER(c_uint8), c_size_t]
_native.abc_sha256_digest.restype = c_int32
_native.abc_sha256_new.argtypes = [POINTER(c_void_p)]
_native.abc_sha256_new.restype = c_int32
_native.abc_sha256_update.argtypes = [c_void_p, c_char_p, c_size_t]
_native.abc_sha256_update.restype = c_int32
_native.abc_sha256_finalize.argtypes = [c_void_p, POINTER(c_uint8), c_size_t]
_native.abc_sha256_finalize.restype = c_int32
_native.abc_sha256_reset.argtypes = [c_void_p]
_native.abc_sha256_reset.restype = c_int32
_native.abc_sha256_free.argtypes = [c_void_p]
_native.abc_sha256_free.restype = None


def _byte_string(data: Buffer) -> bytes:
    if type(data) is bytes:
        return data
    with memoryview(data) as view:
        if view.itemsize != 1:
            raise TypeError("ABC SHA-256 requires a buffer of single-byte items")
        return view.tobytes()


def _check(status: int) -> None:
    if status == 0:
        return
    if status == 2:
        raise OverflowError("The message exceeds the SHA-256 byte length limit")
    if status == 3:
        raise ValueError("The SHA-256 context has already been finalized")
    if status == 5:
        raise MemoryError("Unable to allocate an ABC SHA-256 context")
    raise RuntimeError(f"ABC SHA-256 returned unexpected native status {status}")


def sha256(data: Buffer) -> bytes:
    """Return the 32-byte digest of a byte-oriented buffer."""
    payload = _byte_string(data)
    output = _SHA256_OUTPUT()
    _check(_native.abc_sha256_digest(payload, len(payload), output, len(output)))
    return bytes(output)


class Sha256:
    """Own an ABC SHA-256 state and serialize native calls on that state."""

    __slots__ = ("_lock", "_handle", "_free", "__weakref__")

    def __init__(self) -> None:
        self._lock = Lock()
        self._handle = c_void_p()
        _check(_native.abc_sha256_new(byref(self._handle)))
        try:
            self._free = finalize(self, _native.abc_sha256_free, self._handle)
        except BaseException:
            _native.abc_sha256_free(self._handle)
            raise

    def __copy__(self):
        raise TypeError("SHA-256 context ownership cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("SHA-256 context ownership cannot be copied")

    def _open_handle(self) -> c_void_p:
        if not self._free.alive:
            raise ValueError("The SHA-256 context is closed")
        return self._handle

    def update(self, data: Buffer) -> None:
        """Add bytes to the current message."""
        payload = _byte_string(data)
        with self._lock:
            _check(_native.abc_sha256_update(self._open_handle(), payload, len(payload)))

    def finalize(self) -> bytes:
        """Return the digest and require reset before accepting more input."""
        output = _SHA256_OUTPUT()
        with self._lock:
            _check(_native.abc_sha256_finalize(self._open_handle(), output, len(output)))
        return bytes(output)

    def reset(self) -> None:
        """Reset an open context for a new message."""
        with self._lock:
            _check(_native.abc_sha256_reset(self._open_handle()))

    def close(self) -> None:
        """Release the native context. Repeating this call is safe."""
        with self._lock:
            self._free()

    def __enter__(self) -> "Sha256":
        with self._lock:
            self._open_handle()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
