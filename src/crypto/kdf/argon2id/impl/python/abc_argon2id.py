"""RFC 9106 Argon2id with the native cryptography OpenSSL provider."""
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from src.crypto.providers.python.bytes_input import view

_UINT32 = (1 << 32) - 1


def _parameters(memory_kib, passes, lanes):
    if (any(type(value) is not int for value in (memory_kib, passes, lanes))
            or not 1 <= lanes < 1 << 24 or not 1 <= passes <= _UINT32
            or not 8 * lanes <= memory_kib <= _UINT32):
        raise ValueError("Invalid RFC 9106 Argon2id parameters")


def workspace_bytes(memory_kib: int, lanes: int) -> int:
    _parameters(memory_kib, 1, lanes)
    return memory_kib // (4 * lanes) * (4 * lanes) * 1024


def derive(password, salt, *, memory_kib: int, passes: int, lanes: int,
           length: int, memory_limit: int, secret=b"", associated_data=b"") -> bytes:
    _parameters(memory_kib, passes, lanes)
    if (type(length) is not int or not 4 <= length <= _UINT32
            or type(memory_limit) is not int or workspace_bytes(memory_kib, lanes) + length > memory_limit):
        raise ValueError("Argon2id memory and output must fit the caller budget")
    password, salt, secret, associated_data = map(view, (password, salt, secret, associated_data))
    if len(salt) < 8 or any(len(item) > _UINT32 for item in (password, salt, secret, associated_data)):
        raise ValueError("Invalid Argon2id byte input lengths")
    password, salt, secret, associated_data = map(bytes, (password, salt, secret, associated_data))
    kdf = Argon2id(salt=salt, length=length, iterations=passes, lanes=lanes,
                   memory_cost=memory_kib, secret=secret or None, ad=associated_data or None)
    return kdf.derive(password)
