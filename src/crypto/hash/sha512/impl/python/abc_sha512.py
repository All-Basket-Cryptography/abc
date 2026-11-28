"""Byte-oriented FIPS 180-4 SHA-512 implemented in Python."""

from struct import pack, unpack_from

BLOCK_SIZE = 128
DIGEST_SIZE = 64
MAX_MESSAGE_BYTES = (1 << 125) - 1
_LENGTH_START = BLOCK_SIZE - 16
_MASK = (1 << 64) - 1

_INITIAL = (
    0x6a09e667f3bcc908,  0xbb67ae8584caa73b,  0x3c6ef372fe94f82b,  0xa54ff53a5f1d36f1,
    0x510e527fade682d1,  0x9b05688c2b3e6c1f,  0x1f83d9abfb41bd6b,  0x5be0cd19137e2179,
)
_CONSTANTS = (
    0x428a2f98d728ae22,  0x7137449123ef65cd,  0xb5c0fbcfec4d3b2f,  0xe9b5dba58189dbbc,
    0x3956c25bf348b538,  0x59f111f1b605d019,  0x923f82a4af194f9b,  0xab1c5ed5da6d8118,
    0xd807aa98a3030242,  0x12835b0145706fbe,  0x243185be4ee4b28c,  0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,  0x80deb1fe3b1696b1,  0x9bdc06a725c71235,  0xc19bf174cf692694,
    0xe49b69c19ef14ad2,  0xefbe4786384f25e3,  0x0fc19dc68b8cd5b5,  0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,  0x4a7484aa6ea6e483,  0x5cb0a9dcbd41fbd4,  0x76f988da831153b5,
    0x983e5152ee66dfab,  0xa831c66d2db43210,  0xb00327c898fb213f,  0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,  0xd5a79147930aa725,  0x06ca6351e003826f,  0x142929670a0e6e70,
    0x27b70a8546d22ffc,  0x2e1b21385c26c926,  0x4d2c6dfc5ac42aed,  0x53380d139d95b3df,
    0x650a73548baf63de,  0x766a0abb3c77b2a8,  0x81c2c92e47edaee6,  0x92722c851482353b,
    0xa2bfe8a14cf10364,  0xa81a664bbc423001,  0xc24b8b70d0f89791,  0xc76c51a30654be30,
    0xd192e819d6ef5218,  0xd69906245565a910,  0xf40e35855771202a,  0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,  0x1e376c085141ab53,  0x2748774cdf8eeb99,  0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,  0x4ed8aa4ae3418acb,  0x5b9cca4f7763e373,  0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,  0x78a5636f43172f60,  0x84c87814a1f0ab72,  0x8cc702081a6439ec,
    0x90befffa23631e28,  0xa4506cebde82bde9,  0xbef9a3f7b2c67915,  0xc67178f2e372532b,
    0xca273eceea26619c,  0xd186b8c721c0c207,  0xeada7dd6cde0eb1e,  0xf57d4f7fee6ed178,
    0x06f067aa72176fba,  0x0a637dc5a2c898a6,  0x113f9804bef90dae,  0x1b710b35131c471b,
    0x28db77f523047d84,  0x32caab7b40c72493,  0x3c9ebe0a15c9bebc,  0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,  0x597f299cfc657e2a,  0x5fcb6fab3ad6faec,  0x6c44198c4a475817,
)


def _rotr(word: int, distance: int) -> int:
    return ((word >> distance) | (word << (64 - distance))) & _MASK


def _compress(state: list[int], data: bytes | bytearray | memoryview, offset: int = 0) -> None:
    schedule = list(unpack_from(">16Q", data, offset))
    for index in range(16, 80):
        a, b = schedule[index - 15], schedule[index - 2]
        lower0 = _rotr(a, 1) ^ _rotr(a, 8) ^ (a >> 7)
        lower1 = _rotr(b, 19) ^ _rotr(b, 61) ^ (b >> 6)
        schedule.append((lower1 + schedule[index - 7] + lower0 + schedule[index - 16]) & _MASK)

    a, b, c, d, e, f, g, h = state
    for word, constant in zip(schedule, _CONSTANTS, strict=True):
        upper1 = _rotr(e, 14) ^ _rotr(e, 18) ^ _rotr(e, 41)
        choose = (e & f) ^ (~e & g)
        first = h + upper1 + choose + constant + word
        upper0 = _rotr(a, 28) ^ _rotr(a, 34) ^ _rotr(a, 39)
        majority = (a & b) ^ (a & c) ^ (b & c)
        second = upper0 + majority
        a, b, c, d, e, f, g, h = (first + second) & _MASK, a, b, c, (d + first) & _MASK, e, f, g
    for index, word in enumerate((a, b, c, d, e, f, g, h)):
        state[index] = (state[index] + word) & _MASK


class Sha512:
    """A streaming SHA-512 digest that supports non-destructive snapshots."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        """Start an empty message."""
        self._state = list(_INITIAL)
        self._tail = bytearray()
        self._length = 0

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Append a one-dimensional byte buffer."""
        view = memoryview(data)
        if view.ndim != 1 or view.itemsize != 1:
            raise TypeError("SHA-512 accepts one-dimensional single-byte buffers")
        length = len(view)
        if length > MAX_MESSAGE_BYTES - self._length:
            raise OverflowError("SHA-512 input exceeds the 128-bit bit-length domain")
        if not view.c_contiguous:
            view = memoryview(view.tobytes())
        view = view.cast("B")

        self._length += length
        offset = 0
        if self._tail:
            offset = min(length, BLOCK_SIZE - len(self._tail))
            self._tail.extend(view[:offset])
            if len(self._tail) < BLOCK_SIZE:
                return
            _compress(self._state, self._tail)
            self._tail.clear()
        while offset + BLOCK_SIZE <= length:
            _compress(self._state, view, offset)
            offset += BLOCK_SIZE
        self._tail.extend(view[offset:])

    def digest(self) -> bytes:
        """Return the digest of the current message and keep the stream open."""
        state = self._state.copy()
        zeroes = (_LENGTH_START - 1 - len(self._tail)) % BLOCK_SIZE
        bit_length = (self._length << 3).to_bytes(16, "big")
        padded = bytes(self._tail) + b"\x80" + bytes(zeroes) + bit_length
        for offset in range(0, len(padded), BLOCK_SIZE):
            _compress(state, padded, offset)
        return pack(">8Q", *state)


def sha512(data: bytes | bytearray | memoryview) -> bytes:
    """Return the digest of a single byte buffer."""
    context = Sha512()
    context.update(data)
    return context.digest()
