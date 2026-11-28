"""Deterministic RFC 6979 P-256/SHA-256 with raw P1363 signatures."""
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


def sign(key, message) -> bytes:
    result = _private(key).sign(snapshot(message), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = utils.decode_dss_signature(result)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


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
