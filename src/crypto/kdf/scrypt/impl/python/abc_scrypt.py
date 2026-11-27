"""RFC 7914 scrypt with native Python Salsa20/8 and ROMix."""

from importlib import import_module
from struct import Struct
from sys import maxsize


_pbkdf2 = import_module("src.crypto.kdf.pbkdf2-hmac-sha256.impl.python.abc_pbkdf2_sha256")
_WORDS = Struct("<16I")
_INTEGER = Struct("<Q")
_MASK = (1 << 32) - 1
_ZERO_PAGE = bytes(4096)


def _parameters(cost, block_size, parallel):
    if any(type(value) is not int for value in (cost, block_size, parallel)):
        raise TypeError("scrypt parameters must be integers")
    if (cost <= 1 or cost & (cost - 1) or block_size <= 0 or parallel <= 0
            or block_size <= (cost.bit_length() - 1) // 16):
        raise ValueError("Invalid RFC 7914 scrypt parameters")
    stride = 128 * block_size
    lanes = stride * parallel
    if lanes > _pbkdf2.MAX_OUTPUT_BYTES:
        raise ValueError("scrypt input lanes exceed the PBKDF2 length domain")
    table = stride * cost
    if lanes + table + stride > maxsize:
        raise OverflowError("scrypt workspace cannot fit in a Python buffer")
    return stride, lanes, table


def workspace_size(*, cost: int, block_size: int, parallel: int) -> int:
    """Return the bytes for input lanes, the ROMix table and BlockMix scratch."""
    return sum(_parameters(cost, block_size, parallel))


def derive(password, salt, *, cost: int, block_size: int, parallel: int,
           length: int, memory_limit: int) -> bytes:
    """Return a new scrypt key after checking the explicit buffer budget."""
    stride, lanes, table = _parameters(cost, block_size, parallel)
    if type(length) is not int or not 1 <= length <= _pbkdf2.MAX_OUTPUT_BYTES:
        raise ValueError("scrypt output length exceeds the PBKDF2 domain")
    if type(memory_limit) is not int or memory_limit < lanes + table + stride + length:
        raise ValueError("scrypt workspace and output exceed the memory budget")
    data = bytearray(_pbkdf2.derive(password, salt, 1, lanes))
    try:
        scratch = bytearray(table + stride)
        try:
            memory = memoryview(scratch)
            for offset in range(0, lanes, stride):
                _romix(memoryview(data)[offset:offset + stride], memory[:table],
                       memory[table:], cost)
            return _pbkdf2.derive(password, data, 1, length)
        finally:
            _wipe(scratch)
    finally:
        _wipe(data)


def _wipe(buffer: bytearray) -> None:
    for offset in range(0, len(buffer), len(_ZERO_PAGE)):
        count = min(len(buffer) - offset, len(_ZERO_PAGE))
        buffer[offset:offset + count] = _ZERO_PAGE[:count]


def _romix(lane: memoryview, table: memoryview, temporary: memoryview, cost: int) -> None:
    stride = len(lane)
    for index in range(cost):
        table[index * stride:(index + 1) * stride] = lane
        _blockmix(lane, temporary)
    for _ in range(cost):
        index = _INTEGER.unpack_from(lane, stride - _WORDS.size)[0] & (cost - 1)
        start = index * stride
        for offset in range(stride):
            lane[offset] ^= table[start + offset]
        _blockmix(lane, temporary)


def _blockmix(lane: memoryview, temporary: memoryview) -> None:
    blocks = len(lane) // _WORDS.size
    state = list(_WORDS.unpack_from(lane, len(lane) - _WORDS.size))
    for i in range(blocks):
        for j, word in enumerate(_WORDS.unpack_from(lane, i * _WORDS.size)):
            state[j] ^= word
        _salsa8(state)
        index = i // 2 + (i % 2) * (blocks // 2)
        _WORDS.pack_into(temporary, index * _WORDS.size, *state)
    lane[:] = temporary


def _rotate(word: int, count: int) -> int:
    word &= _MASK
    return ((word << count) | (word >> (32 - count))) & _MASK


def _quarter(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[b] ^= _rotate(state[a] + state[d], 7)
    state[c] ^= _rotate(state[b] + state[a], 9)
    state[d] ^= _rotate(state[c] + state[b], 13)
    state[a] ^= _rotate(state[d] + state[c], 18)


def _salsa8(state: list[int]) -> None:
    work = state.copy()
    for _ in range(4):
        _quarter(work, 0, 4, 8, 12)
        _quarter(work, 5, 9, 13, 1)
        _quarter(work, 10, 14, 2, 6)
        _quarter(work, 15, 3, 7, 11)
        _quarter(work, 0, 1, 2, 3)
        _quarter(work, 5, 6, 7, 4)
        _quarter(work, 10, 11, 8, 9)
        _quarter(work, 15, 12, 13, 14)
    for i, word in enumerate(work):
        state[i] = (state[i] + word) & _MASK
