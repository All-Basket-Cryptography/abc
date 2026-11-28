"""Deterministic RFC 6979 P-256/SHA-256 with raw P1363 signatures."""
import ctypes as C
from functools import lru_cache
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from src.crypto.providers.python.bytes_input import fixed, snapshot, view

_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_CURVE = ec.SECP256R1()


def _private(key):
    scalar = int.from_bytes(fixed(key, 32), "big")
    if not 1 <= scalar < _ORDER:
        raise ValueError("Invalid P-256 private scalar")
    return ec.derive_private_key(scalar, _CURVE)


def public_key(key) -> bytes:
    return _private(key).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


class DeterministicSigner:
    """Sign through a trusted build of the ABC C ECDSA engine."""

    def __init__(self, library):
        path = Path(library)
        if not path.is_absolute():
            raise ValueError("The ABC ECDSA library path must be absolute")
        try:
            handle = C.CDLL(str(path.resolve(strict=True)))
            self._sign = handle.abc_ecdsa_p256_sha256_c_sign
        except (OSError, AttributeError) as error:
            raise RuntimeError("Unable to load the ABC C ECDSA signing engine") from error
        self._sign.argtypes = [C.c_char_p, C.c_char_p, C.c_size_t, C.c_void_p]
        self._sign.restype = C.c_int
        self._library = handle

    def sign(self, key, message) -> bytes:
        scalar = fixed(key, 32)
        data = snapshot(message)
        output = (C.c_ubyte * 64)()
        status = self._sign(scalar, data, len(data), output)
        if status == 1:
            raise ValueError("Invalid P-256 private scalar")
        if status == 5:
            raise RuntimeError("The RFC 6979 candidate limit was exhausted")
        if status != 0:
            raise RuntimeError("The ABC C ECDSA signing engine failed")
        return bytes(output)


@lru_cache(maxsize=4)
def _configured_signer(library: str) -> DeterministicSigner:
    return DeterministicSigner(library)


def sign(key, message) -> bytes:
    library = os.environ.get("ABC_ECDSA_P256_LIBRARY")
    if not library:
        raise RuntimeError("Set ABC_ECDSA_P256_LIBRARY or use DeterministicSigner")
    return _configured_signer(library).sign(key, message)


def verify(key, message, signature) -> bool:
    key, signature = view(key), view(signature)
    if len(signature) != 64 or len(key) not in (33, 65):
        return False
    key, signature = bytes(key), bytes(signature)
    if (len(key) == 33 and key[0] not in (2, 3)) or (len(key) == 65 and key[0] != 4):
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not 1 <= r < _ORDER or not 1 <= s < _ORDER:
        return False
    data = snapshot(message)
    try:
        point = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, key)
        point.verify(utils.encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True
