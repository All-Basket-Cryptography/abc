"""Unkeyed sequential BLAKE2b with a caller-selected output size."""

from operator import index
from struct import Struct


BLOCK_SIZE = 128
MAX_DIGEST_SIZE = 64
MAX_MESSAGE_BYTES = (1 << 128) - 1
BytesLike = bytes | bytearray | memoryview
_MASK = (1 << 64) - 1
_WORDS = Struct("<16Q")
_DIGEST = Struct("<8Q")
_IV = (
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
)
_SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)


def _rotr(word: int, distance: int) -> int:
    return (word >> distance) | ((word << (64 - distance)) & _MASK)


def _mix(v: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    v[a] = (v[a] + v[b] + x) & _MASK
    v[d] = _rotr(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & _MASK
    v[b] = _rotr(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + y) & _MASK
    v[d] = _rotr(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & _MASK
    v[b] = _rotr(v[b] ^ v[c], 63)


def _compress(state: list[int], data: BytesLike, offset: int, length: int, final: bool) -> None:
    words = _WORDS.unpack_from(data, offset)
    v = state + list(_IV)
    v[12] ^= length & _MASK
    v[13] ^= length >> 64
    if final:
        v[14] ^= _MASK
    for round_index in range(12):
        s = _SIGMA[round_index % 10]
        _mix(v, 0, 4, 8, 12, words[s[0]], words[s[1]])
        _mix(v, 1, 5, 9, 13, words[s[2]], words[s[3]])
        _mix(v, 2, 6, 10, 14, words[s[4]], words[s[5]])
        _mix(v, 3, 7, 11, 15, words[s[6]], words[s[7]])
        _mix(v, 0, 5, 10, 15, words[s[8]], words[s[9]])
        _mix(v, 1, 6, 11, 12, words[s[10]], words[s[11]])
        _mix(v, 2, 7, 8, 13, words[s[12]], words[s[13]])
        _mix(v, 3, 4, 9, 14, words[s[14]], words[s[15]])
    for i in range(8):
        state[i] ^= v[i] ^ v[i + 8]


class Blake2b:
    """Byte-aligned BLAKE2b context with non-destructive digest snapshots."""

    def __init__(self, digest_size: int = MAX_DIGEST_SIZE) -> None:
        size = index(digest_size)
        if not 1 <= size <= MAX_DIGEST_SIZE:
            raise ValueError("BLAKE2b digest size must be between 1 and 64 bytes")
        self._digest_size = size
        self.reset()

    def reset(self) -> None:
        self._state = list(_IV)
        self._state[0] ^= 0x01010000 | self._digest_size
        self._tail = bytearray()
        self._length = 0

    def update(self, data: BytesLike) -> None:
        view = memoryview(data)
        if view.ndim != 1 or view.itemsize != 1:
            raise TypeError("expected a one-dimensional single-byte buffer")
        length = self._length + len(view)
        if length > MAX_MESSAGE_BYTES:
            raise OverflowError("BLAKE2b message exceeds its 128-bit byte counter")
        if not len(view):
            return
        view = view.cast("B") if view.c_contiguous else memoryview(view.tobytes())

        compressed = self._length - len(self._tail)
        self._length = length
        offset = 0
        if self._tail:
            offset = min(BLOCK_SIZE - len(self._tail), len(view))
            self._tail.extend(view[:offset])
            if offset == len(view):
                return
            compressed += BLOCK_SIZE
            _compress(self._state, self._tail, 0, compressed, False)
            self._tail.clear()
        while offset + BLOCK_SIZE < len(view):
            compressed += BLOCK_SIZE
            _compress(self._state, view, offset, compressed, False)
            offset += BLOCK_SIZE
        self._tail.extend(view[offset:])

    def digest(self) -> bytes:
        block = self._tail.ljust(BLOCK_SIZE, b"\0")
        state = self._state.copy()
        _compress(state, block, 0, self._length, True)
        return _DIGEST.pack(*state)[:self._digest_size]


def blake2b(data: BytesLike, digest_size: int = MAX_DIGEST_SIZE) -> bytes:
    context = Blake2b(digest_size)
    context.update(data)
    return context.digest()
