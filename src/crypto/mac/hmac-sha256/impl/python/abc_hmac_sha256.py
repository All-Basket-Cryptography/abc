"""RFC 2104 HMAC with the ABC Python SHA-256 core."""

from src.crypto.hash.sha256.impl.python.abc_sha256 import MAX_MESSAGE_BYTES, Sha256, sha256


TAG_BYTES = 32
BLOCK_BYTES = 64
MAX_INPUT_BYTES = MAX_MESSAGE_BYTES - BLOCK_BYTES
BytesLike = bytes | bytearray | memoryview


def byte_view(data: BytesLike) -> memoryview:
    view = memoryview(data)
    if view.ndim != 1 or view.itemsize != 1:
        raise TypeError("expected a one-dimensional single-byte buffer")
    return view


class HmacSha256:
    """Streaming HMAC with a fixed key and non-destructive digest snapshots."""

    def __init__(self, key: BytesLike) -> None:
        key_view = byte_view(key)
        material = sha256(key_view) if len(key_view) > BLOCK_BYTES else key_view.tobytes()
        block = material.ljust(BLOCK_BYTES, b"\0")
        self._inner_pad = bytes(byte ^ 0x36 for byte in block)
        self._outer_pad = bytes(byte ^ 0x5C for byte in block)
        self._inner = Sha256()
        self._inner.update(self._inner_pad)

    def reset(self) -> None:
        """Start another message with this key."""
        self._inner.reset()
        self._inner.update(self._inner_pad)

    def update(self, data: BytesLike) -> None:
        """Append a byte buffer to the authenticated message."""
        self._inner.update(data)

    def digest(self) -> bytes:
        """Read a complete tag without closing the context."""
        return sha256(self._outer_pad + self._inner.digest())


def authenticate(key: BytesLike, message: BytesLike) -> bytes:
    """Return the complete HMAC-SHA-256 tag."""
    context = HmacSha256(key)
    context.update(message)
    return context.digest()
