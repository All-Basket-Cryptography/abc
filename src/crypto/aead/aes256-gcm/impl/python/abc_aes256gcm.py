"""SP 800-38D AES-256-GCM for 96-bit nonces and detached full tags."""

from hmac import compare_digest
from importlib import import_module
from struct import Struct

Aes256 = import_module("src.crypto.cipher.aes256.impl.python.abc_aes256").Aes256
BLOCK_BYTES = 16
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_MESSAGE_BYTES = ((1 << 32) - 2) * BLOCK_BYTES
MAX_AAD_BYTES = (1 << 61) - 1
_LENGTHS = Struct(">QQ")
_REDUCTION = 0xe1 << 120


class InvalidTag(ValueError):
    """The supplied data failed authentication."""


def _readable(data):
    return data if type(data) is bytes else memoryview(data).cast("B")


def _inputs(key, nonce, aad, data) -> tuple[bytes, bytes, bytes, bytes]:
    key, nonce, aad, data = map(_readable, (key, nonce, aad, data))
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("AES-256-GCM requires a 32-byte key and 12-byte nonce")
    if len(data) > MAX_MESSAGE_BYTES or len(aad) > MAX_AAD_BYTES:
        raise ValueError("AES-256-GCM input exceeds the profile length limits")
    # An immutable snapshot is shared by authentication and decryption.
    return bytes(key), bytes(nonce), bytes(aad), bytes(data)


def _multiply(value: int, key: int) -> int:
    product = 0
    for bit in range(127, -1, -1):
        product ^= key & -((value >> bit) & 1)
        key = (key >> 1) ^ (_REDUCTION & -(key & 1))
    return product


def _append(accumulator: int, key: int, message: bytes) -> int:
    for offset in range(0, len(message), BLOCK_BYTES):
        part = message[offset:offset + BLOCK_BYTES]
        word = int.from_bytes(part, "big") << (8 * (BLOCK_BYTES - len(part)))
        accumulator = _multiply(accumulator ^ word, key)
    return accumulator


def _apply(aes: Aes256, nonce: bytes, value: bytes) -> bytes:
    output = bytearray(len(value))
    for offset in range(0, len(value), BLOCK_BYTES):
        part = value[offset:offset + BLOCK_BYTES]
        counter = offset // BLOCK_BYTES + 2
        pad = aes.encrypt(nonce + counter.to_bytes(4, "big"))
        output[offset:offset + len(part)] = bytes(a ^ b for a, b in zip(part, pad))
    return bytes(output)


def _tag(aes: Aes256, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    key = int.from_bytes(aes.encrypt(bytes(BLOCK_BYTES)), "big")
    accumulator = _append(_append(0, key, aad), key, ciphertext)
    footer = _LENGTHS.pack(len(aad) * 8, len(ciphertext) * 8)
    digest = _multiply(accumulator ^ int.from_bytes(footer, "big"), key)
    mask = int.from_bytes(aes.encrypt(nonce + b"\0\0\0\1"), "big")
    return (digest ^ mask).to_bytes(TAG_BYTES, "big")


def seal_detached(key, nonce, plaintext, aad=b"") -> tuple[bytes, bytes]:
    """Encrypt with a fresh nonce and return the ciphertext and detached tag."""
    key, nonce, aad, plaintext = _inputs(key, nonce, aad, plaintext)
    aes = Aes256(key)
    ciphertext = _apply(aes, nonce, plaintext)
    return ciphertext, _tag(aes, nonce, aad, ciphertext)


def open_detached(key, nonce, ciphertext, tag, aad=b"") -> bytes:
    """Authenticate an immutable ciphertext snapshot before decrypting it."""
    tag = bytes(_readable(tag))
    if len(tag) != TAG_BYTES:
        raise InvalidTag("AES-256-GCM authentication failed")
    key, nonce, aad, ciphertext = _inputs(key, nonce, aad, ciphertext)
    aes = Aes256(key)
    if not compare_digest(_tag(aes, nonce, aad, ciphertext), tag):
        raise InvalidTag("AES-256-GCM authentication failed")
    return _apply(aes, nonce, ciphertext)
