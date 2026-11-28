"""Pure Python RFC 8439 one-time authenticator."""


KEY_BYTES = 32
TAG_BYTES = 16
_BLOCK_BYTES = 16
_CLAMP_MASK = 0x0ffffffc0ffffffc0ffffffc0fffffff
_PRIME = (1 << 130) - 5
_TAG_MASK = (1 << 128) - 1


class Mac:
    """An incremental one-message authenticator under a fresh one-time key."""

    __slots__ = ("_r", "_s", "_residue", "_pending", "_tag")

    def __init__(self, key):
        key = memoryview(key).cast("B")
        if len(key) != KEY_BYTES:
            raise ValueError("Poly1305 requires a 32-byte one-time key")
        self._r = int.from_bytes(key[:_BLOCK_BYTES], "little") & _CLAMP_MASK
        self._s = int.from_bytes(key[_BLOCK_BYTES:], "little")
        self._residue = 0
        self._pending = bytearray()
        self._tag = None

    def _absorb(self, block) -> None:
        value = int.from_bytes(block, "little") | (1 << (8 * len(block)))
        self._residue = ((self._residue + value) * self._r) % _PRIME

    def update(self, input_bytes) -> None:
        """Absorb bytes and own any trailing partial block."""
        if self._tag is not None:
            raise ValueError("Poly1305 has already finalized")
        source = memoryview(input_bytes).cast("B")
        if self._pending:
            consumed = min(_BLOCK_BYTES - len(self._pending), len(source))
            self._pending.extend(source[:consumed])
            if len(self._pending) < _BLOCK_BYTES:
                return
            self._absorb(self._pending)
            self._pending.clear()
            source = source[consumed:]
        full_width = len(source) - len(source) % _BLOCK_BYTES
        for offset in range(0, full_width, _BLOCK_BYTES):
            self._absorb(source[offset:offset + _BLOCK_BYTES])
        self._pending.extend(source[full_width:])

    def finish(self) -> bytes:
        """Close the message and return its tag on every subsequent call."""
        if self._tag is None:
            if self._pending:
                self._absorb(self._pending)
            self._tag = ((self._residue + self._s) & _TAG_MASK).to_bytes(TAG_BYTES, "little")
            self._r = self._s = self._residue = 0
            self._pending.clear()
        return self._tag


def authenticate(key, input_bytes) -> bytes:
    """Authenticate one complete message under a fresh one-time key."""
    mac = Mac(key)
    mac.update(input_bytes)
    return mac.finish()
