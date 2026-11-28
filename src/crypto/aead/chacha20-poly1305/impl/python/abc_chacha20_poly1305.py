"""RFC 8439 detached AEAD using the ABC Python primitives."""

from hmac import compare_digest
from importlib import import_module
from struct import Struct


_chacha = import_module("src.crypto.cipher.chacha20.impl.python.abc_chacha20")
_poly = import_module("src.crypto.mac.poly1305.impl.python.abc_poly1305")
KEY_BYTES = _chacha.KEY_BYTES
NONCE_BYTES = _chacha.NONCE_BYTES
TAG_BYTES = _poly.TAG_BYTES
_LENGTHS = Struct("<QQ")
_MAX_AAD_BYTES = (1 << 64) - 1
_ZEROES = bytes(16)


class InvalidTag(ValueError):
    """The detached tag failed authentication."""


def _readable(data):
    if type(data) is bytes:
        return data
    return memoryview(data).cast("B")


def _check_lengths(data_bytes: int, aad_bytes: int) -> None:
    if not _chacha.fits_counter(data_bytes, 1):
        raise ValueError("ChaCha20-Poly1305 payload exceeds the counter domain")
    if not 0 <= aad_bytes <= _MAX_AAD_BYTES:
        raise ValueError("ChaCha20-Poly1305 associated data exceeds the length domain")


def _snapshot(key, nonce, data, aad):
    key, nonce = _readable(key), _readable(nonce)
    data, aad = _readable(data), _readable(aad)
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("ChaCha20-Poly1305 requires a 32-byte key and a 12-byte nonce")
    _check_lengths(len(data), len(aad))
    # Seal and open use one immutable snapshot of each caller buffer.
    return bytes(key), bytes(nonce), bytes(data), bytes(aad)


def _update_padded(mac, data: bytes) -> None:
    mac.update(data)
    mac.update(_ZEROES[:(-len(data) % 16)])


def _tag(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    mask = _chacha.block(key, nonce, 0)[:_poly.KEY_BYTES]
    mac = _poly.Mac(mask)
    _update_padded(mac, aad)
    _update_padded(mac, ciphertext)
    mac.update(_LENGTHS.pack(len(aad), len(ciphertext)))
    return mac.finish()


def seal_detached(key, nonce, plaintext, aad=b"") -> tuple[bytes, bytes]:
    """Return the ciphertext and full 16-byte tag. Use a fresh nonce per key."""
    key, nonce, plaintext, aad = _snapshot(key, nonce, plaintext, aad)
    ciphertext = _chacha.xor(key, nonce, 1, plaintext)
    return ciphertext, _tag(key, nonce, ciphertext, aad)


def open_detached(key, nonce, ciphertext, tag, aad=b"") -> bytes:
    """Authenticate a ciphertext snapshot before computing plaintext."""
    wire = _readable(tag)
    if len(wire) != TAG_BYTES:
        raise InvalidTag("ChaCha20-Poly1305 authentication failed")
    wire = bytes(wire)
    key, nonce, ciphertext, aad = _snapshot(key, nonce, ciphertext, aad)
    if not compare_digest(_tag(key, nonce, ciphertext, aad), wire):
        raise InvalidTag("ChaCha20-Poly1305 authentication failed")
    return _chacha.xor(key, nonce, 1, ciphertext)


def _destination(output, width: int) -> memoryview:
    destination = memoryview(output).cast("B")
    if destination.readonly:
        raise TypeError("ChaCha20-Poly1305 requires a writable destination")
    if len(destination) < width:
        raise ValueError("ChaCha20-Poly1305 destination is shorter than the input")
    return destination


def seal_into(key, nonce, plaintext, output, aad=b"") -> bytes:
    """Write the ciphertext prefix, then return its detached tag."""
    source = _readable(plaintext)
    destination = _destination(output, len(source))
    ciphertext, tag = seal_detached(key, nonce, source, aad)
    destination[:len(ciphertext)] = ciphertext
    return tag


def open_into(key, nonce, ciphertext, tag, output, aad=b"") -> None:
    """Write an authenticated plaintext prefix. An error leaves output unchanged."""
    source = _readable(ciphertext)
    destination = _destination(output, len(source))
    plaintext = open_detached(key, nonce, source, tag, aad)
    destination[:len(plaintext)] = plaintext
