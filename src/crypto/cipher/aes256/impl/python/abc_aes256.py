"""Portable, table-free AES-256 block encryption and decryption (FIPS 197)."""

KEY_BYTES = 32
BLOCK_BYTES = 16
_ROUNDS = 14


def _input(data) -> bytes:
    return data if type(data) is bytes else bytes(memoryview(data).cast("B"))


def _xtime(value: int) -> int:
    return ((value << 1) & 255) ^ (0x1b & -(value >> 7))


def _multiply(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        result ^= left & -(right & 1)
        left = _xtime(left)
        right >>= 1
    return result


def _square(value: int) -> int:
    spread = (value | (value << 4)) & 0x0f0f
    spread = (spread | (spread << 2)) & 0x3333
    spread = (spread | (spread << 1)) & 0x5555
    high = spread >> 8
    folded = (spread & 255) ^ high ^ (high << 1) ^ (high << 3) ^ (high << 4)
    high = folded >> 8
    return (folded ^ high ^ (high << 1) ^ (high << 3) ^ (high << 4)) & 255


def _inverse(value: int) -> int:
    squared = _square(value)
    cube = _multiply(squared, value)
    seventh = _multiply(_square(cube), value)
    fifteenth = _multiply(_square(seventh), value)
    one_hundred_twentieth = _square(_square(_square(fifteenth)))
    return _square(_multiply(one_hundred_twentieth, seventh))


def _rotate(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (8 - amount))) & 255


def _substitute(value: int) -> int:
    x = _inverse(value)
    return x ^ _rotate(x, 1) ^ _rotate(x, 2) ^ _rotate(x, 3) ^ _rotate(x, 4) ^ 0x63


def _inverse_substitute(value: int) -> int:
    return _inverse(_rotate(value, 1) ^ _rotate(value, 3) ^ _rotate(value, 6) ^ 5)


def _expand(key: bytes) -> bytes:
    words = bytearray(BLOCK_BYTES * (_ROUNDS + 1))
    words[:KEY_BYTES] = key
    rc = 1
    for offset in range(KEY_BYTES, len(words), 4):
        a, b, c, d = words[offset - 4:offset]
        if offset % 32 == 0:
            a, b, c, d = _substitute(b) ^ rc, _substitute(c), _substitute(d), _substitute(a)
            rc = _xtime(rc)
        elif offset % 32 == 16:
            a, b, c, d = _substitute(a), _substitute(b), _substitute(c), _substitute(d)
        for index, value in enumerate((a, b, c, d), start=offset):
            words[index] = words[index - KEY_BYTES] ^ value
    return bytes(words)


def _add_key(state: bytearray, words: bytes, round_index: int) -> None:
    position = BLOCK_BYTES * round_index
    for index in range(BLOCK_BYTES):
        state[index] ^= words[position + index]


def _shift_rows(state: bytearray, direction: int) -> None:
    for row in range(1, 4):
        row_bytes = state[row::4]
        shift = (direction * row) & 3
        state[row::4] = row_bytes[shift:] + row_bytes[:shift]


def _mix_columns(state: bytearray, reverse: bool) -> None:
    for offset in range(0, BLOCK_BYTES, 4):
        a, b, c, d = state[offset:offset + 4]
        if reverse:
            even, odd = _xtime(_xtime(a ^ c)), _xtime(_xtime(b ^ d))
            a, b, c, d = a ^ even, b ^ odd, c ^ even, d ^ odd
        total = a ^ b ^ c ^ d
        state[offset:offset + 4] = (
            a ^ total ^ _xtime(a ^ b), b ^ total ^ _xtime(b ^ c),
            c ^ total ^ _xtime(c ^ d), d ^ total ^ _xtime(d ^ a),
        )


class Aes256:
    """Store the expanded key for independent fixed-width block operations."""

    __slots__ = ("_round_keys",)

    def __init__(self, key):
        data = _input(key)
        if len(data) != KEY_BYTES:
            raise ValueError("AES-256 requires a 32-byte key")
        self._round_keys = _expand(data)

    def encrypt(self, block) -> bytes:
        state = bytearray(_input(block))
        if len(state) != BLOCK_BYTES:
            raise ValueError("AES-256 requires a 16-byte block")
        _add_key(state, self._round_keys, 0)
        for round_index in range(1, _ROUNDS + 1):
            for index in range(BLOCK_BYTES):
                state[index] = _substitute(state[index])
            _shift_rows(state, 1)
            if round_index != _ROUNDS:
                _mix_columns(state, False)
            _add_key(state, self._round_keys, round_index)
        return bytes(state)

    def decrypt(self, block) -> bytes:
        state = bytearray(_input(block))
        if len(state) != BLOCK_BYTES:
            raise ValueError("AES-256 requires a 16-byte block")
        _add_key(state, self._round_keys, _ROUNDS)
        for round_index in range(_ROUNDS - 1, -1, -1):
            _shift_rows(state, 3)
            for index in range(BLOCK_BYTES):
                state[index] = _inverse_substitute(state[index])
            _add_key(state, self._round_keys, round_index)
            if round_index != 0:
                _mix_columns(state, True)
        return bytes(state)
