"""FIPS 202 Keccak-p[1600, 24] and byte-aligned 1088-bit-rate sponge."""

from __future__ import annotations

from operator import index
from struct import Struct


RATE_BYTES = 136
BytesLike = bytes | bytearray | memoryview
_RATE = Struct("<17Q")
_DIGEST = Struct("<4Q")
_MASK = (1 << 64) - 1
_ROTATIONS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)
_RHO_PI = tuple(
    (x + 5 * y, x, y + 5 * ((2 * x + 3 * y) % 5), _ROTATIONS[x + 5 * y])
    for y in range(5)
    for x in range(5)
)
_IOTA = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def _rotl(word: int, amount: int) -> int:
    return ((word << amount) & _MASK) | (word >> (64 - amount))


def _permute(state: list[int]) -> None:
    """Mutate 25 unsigned 64-bit lanes in x + 5*y order."""
    parity = [0] * 5
    moves = [0] * 25
    for round_constant in _IOTA:
        for x in range(5):
            parity[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
        theta = [parity[(x - 1) % 5] ^ _rotl(parity[(x + 1) % 5], 1) for x in range(5)]
        for source, column, target, rotation in _RHO_PI:
            moves[target] = _rotl(state[source] ^ theta[column], rotation)
        for row in range(0, 25, 5):
            a, b, c, d, e = moves[row:row + 5]
            state[row:row + 5] = (
                a ^ (~b & c), b ^ (~c & d), c ^ (~d & e), d ^ (~e & a), e ^ (~a & b),
            )
        state[0] ^= round_constant


def _absorb(lanes: list[int], block: BytesLike, offset: int = 0) -> None:
    for lane, word in enumerate(_RATE.unpack_from(block, offset)):
        lanes[lane] ^= word
    _permute(lanes)


def _byte_view(data: BytesLike) -> memoryview:
    view = memoryview(data)
    if view.ndim != 1 or view.itemsize != 1:
        raise TypeError("expected a one-dimensional single-byte buffer")
    return view


class Sponge:
    """Incrementally absorb bytes and take independent digest or reader snapshots."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._lanes = [0] * 25
        self._tail = bytearray()

    def update(self, data: BytesLike) -> None:
        view = _byte_view(data)
        view = view.cast("B") if view.c_contiguous else memoryview(view.tobytes())
        offset = 0
        if self._tail:
            offset = min(RATE_BYTES - len(self._tail), len(view))
            self._tail.extend(view[:offset])
            if len(self._tail) < RATE_BYTES:
                return
            _absorb(self._lanes, self._tail)
            self._tail.clear()
        while offset + RATE_BYTES <= len(view):
            _absorb(self._lanes, view, offset)
            offset += RATE_BYTES
        self._tail.extend(view[offset:])

    def _finalize(self, suffix: int) -> list[int]:
        block = bytearray(RATE_BYTES)
        block[:len(self._tail)] = self._tail
        block[len(self._tail)] = suffix
        block[-1] |= 0x80
        lanes = self._lanes.copy()
        _absorb(lanes, block)
        return lanes

    def sha3_digest(self) -> bytes:
        return _DIGEST.pack(*self._finalize(0x06)[:4])

    def shake_reader(self) -> ShakeReader:
        return ShakeReader(self._finalize(0x1f))


class ShakeReader:
    """Output stream initialized by Sponge.shake_reader."""

    def __init__(self, lanes: list[int]) -> None:
        self._lanes = lanes
        self._block = _RATE.pack(*self._lanes[:17])
        self._offset = 0

    def readinto(self, destination: bytearray | memoryview) -> int:
        output = _byte_view(destination)
        if output.readonly or not output.c_contiguous:
            raise TypeError("expected a writable contiguous output buffer")
        output = output.cast("B")
        written = 0
        while written < len(output):
            if self._offset == RATE_BYTES:
                _permute(self._lanes)
                self._block = _RATE.pack(*self._lanes[:17])
                self._offset = 0
            count = min(len(output) - written, RATE_BYTES - self._offset)
            output[written:written + count] = self._block[self._offset:self._offset + count]
            self._offset += count
            written += count
        return written

    def read(self, size: int) -> bytes:
        count = index(size)
        if count < 0:
            raise ValueError("SHAKE256 output length must be nonnegative")
        output = bytearray(count)
        self.readinto(output)
        return bytes(output)
