"""Byte-oriented FIPS 180-4 SHA-256 implemented in Python."""

from struct import pack, unpack_from


BLOCK_SIZE = 64
DIGEST_SIZE = 32
MAX_MESSAGE_BYTES = (1 << 61) - 1
_MASK = (1 << 32) - 1

_INITIAL = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
_CONSTANTS = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotr(word: int, distance: int) -> int:
    return ((word >> distance) | (word << (32 - distance))) & _MASK


def _compress(state: list[int], data: bytes | bytearray | memoryview, offset: int = 0) -> None:
    words = list(unpack_from(">16I", data, offset))
    for i in range(16, 64):
        x, y = words[i - 15], words[i - 2]
        small0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        small1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
        words.append((words[i - 16] + small0 + words[i - 7] + small1) & _MASK)

    a, b, c, d, e, f, g, h = state
    for word, constant in zip(words, _CONSTANTS, strict=True):
        choose = (e & f) ^ (~e & g)
        majority = (a & b) ^ (a & c) ^ (b & c)
        first = h + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + choose + constant + word
        second = (_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + majority
        a, b, c, d, e, f, g, h = (first + second) & _MASK, a, b, c, (d + first) & _MASK, e, f, g
    for i, word in enumerate((a, b, c, d, e, f, g, h)):
        state[i] = (state[i] + word) & _MASK


class Sha256:
    """A hash context with streaming updates and non-destructive digest snapshots."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        """Start an empty message."""
        self._state = list(_INITIAL)
        self._tail = bytearray()
        self._length = 0

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Append a byte buffer. Rejected inputs leave the context unchanged."""
        view = memoryview(data)
        if view.ndim != 1 or view.itemsize != 1:
            raise TypeError("SHA-256 accepts one-dimensional single-byte buffers")
        size = len(view)
        if size > MAX_MESSAGE_BYTES - self._length:
            raise OverflowError("SHA-256 input exceeds the 64-bit bit-length domain")
        if not view.c_contiguous:
            view = memoryview(view.tobytes())
        view = view.cast("B")
        self._length += size
        offset = 0
        if self._tail:
            offset = min(size, BLOCK_SIZE - len(self._tail))
            self._tail.extend(view[:offset])
            if len(self._tail) < BLOCK_SIZE:
                return
            _compress(self._state, self._tail)
            self._tail.clear()
        while offset + BLOCK_SIZE <= size:
            _compress(self._state, view, offset)
            offset += BLOCK_SIZE
        self._tail.extend(view[offset:])

    def digest(self) -> bytes:
        """Return the current digest and keep the context open."""
        state = self._state.copy()
        zeroes = (55 - len(self._tail)) % BLOCK_SIZE
        padded = bytes(self._tail) + b"\x80" + bytes(zeroes) + pack(">Q", self._length * 8)
        for offset in range(0, len(padded), BLOCK_SIZE):
            _compress(state, padded, offset)
        return pack(">8I", *state)


def sha256(data: bytes | bytearray | memoryview) -> bytes:
    """Return the SHA-256 digest of a byte buffer."""
    context = Sha256()
    context.update(data)
    return context.digest()
