"""Pure Python RFC 8439 block and one-shot stream cipher."""

from operator import index, xor as xor_octet
from struct import Struct


KEY_BYTES = 32
NONCE_BYTES = 12
BLOCK_BYTES = 64
_COUNTER_DOMAIN = 1 << 32
_WORD_MASK = _COUNTER_DOMAIN - 1
_CONSTANTS = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
_KEY = Struct("<8I")
_NONCE = Struct("<3I")
_BLOCK = Struct("<16I")


def fits_counter(length: int, counter: int) -> bool:
    """Test the RFC payload bound without allocating its input buffer."""
    length = index(length)
    counter = index(counter)
    return (0 <= counter < _COUNTER_DOMAIN and length >= 0
            and (length == 0 or (length - 1) // BLOCK_BYTES < _COUNTER_DOMAIN - counter))


def _initial(key, nonce) -> list[int]:
    key = memoryview(key).cast("B")
    nonce = memoryview(nonce).cast("B")
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("ChaCha20 requires a 32-byte key and 12-byte nonce")
    return [*_CONSTANTS, *_KEY.unpack(key), 0, *_NONCE.unpack(nonce)]


def _rotate(word: int, distance: int) -> int:
    return ((word << distance) | (word >> (32 - distance))) & _WORD_MASK


def _quarter(state: list[int], i: int, j: int, k: int, l: int) -> None:
    a, b, c, d = state[i], state[j], state[k], state[l]
    a = (a + b) & _WORD_MASK
    d = _rotate(d ^ a, 16)
    c = (c + d) & _WORD_MASK
    b = _rotate(b ^ c, 12)
    a = (a + b) & _WORD_MASK
    d = _rotate(d ^ a, 8)
    c = (c + d) & _WORD_MASK
    b = _rotate(b ^ c, 7)
    state[i], state[j], state[k], state[l] = a, b, c, d


def _stream_block(initial: list[int], counter: int) -> bytes:
    initial[12] = counter
    state = initial.copy()
    for _ in range(10):
        _quarter(state, 0, 4, 8, 12)
        _quarter(state, 1, 5, 9, 13)
        _quarter(state, 2, 6, 10, 14)
        _quarter(state, 3, 7, 11, 15)
        _quarter(state, 0, 5, 10, 15)
        _quarter(state, 1, 6, 11, 12)
        _quarter(state, 2, 7, 8, 13)
        _quarter(state, 3, 4, 9, 14)
    return _BLOCK.pack(*((word + original) & _WORD_MASK for word, original in zip(state, initial)))


def block(key, nonce, counter: int) -> bytes:
    """Generate a single 64-byte block."""
    counter = index(counter)
    if not fits_counter(BLOCK_BYTES, counter):
        raise ValueError("ChaCha20 counter is outside uint32")
    return _stream_block(_initial(key, nonce), counter)


def _evaluate(key, nonce, counter: int, source: memoryview) -> bytes:
    counter = index(counter)
    if not fits_counter(len(source), counter):
        raise ValueError("ChaCha20 input exceeds the counter domain")
    initial = _initial(key, nonce)
    result = bytearray(len(source))
    for offset in range(0, len(source), BLOCK_BYTES):
        end = min(offset + BLOCK_BYTES, len(source))
        stream = _stream_block(initial, counter)
        result[offset:end] = bytes(map(xor_octet, source[offset:end], stream))
        counter += 1
    return bytes(result)


def xor(key, nonce, counter: int, input_bytes) -> bytes:
    """Return a new byte string containing the transformed input."""
    return _evaluate(key, nonce, counter, memoryview(input_bytes).cast("B"))


def xor_into(key, nonce, counter: int, input_bytes, output) -> None:
    """Write the destination prefix, permitting overlap with the input."""
    source = memoryview(input_bytes).cast("B")
    destination = memoryview(output).cast("B")
    if destination.readonly:
        raise TypeError("ChaCha20 requires a writable destination")
    if len(destination) < len(source):
        raise ValueError("ChaCha20 destination is shorter than the input")
    destination[:len(source)] = _evaluate(key, nonce, counter, source)
