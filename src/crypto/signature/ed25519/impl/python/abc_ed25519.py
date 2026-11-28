"""Pure Ed25519 with canonical A/R/S and explicit small-order rejection."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from src.crypto.providers.python.bytes_input import fixed, snapshot, view

_P = (1 << 255) - 19
_ORDER = (1 << 252) + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, -1, _P) % _P
_SQRT_MINUS_ONE = pow(2, (_P - 1) // 4, _P)


def _strict_point(wire: bytes) -> bool:
    encoded = int.from_bytes(wire, "little")
    sign, y = encoded >> 255, encoded & ((1 << 255) - 1)
    if y >= _P:
        return False
    y2 = y * y % _P
    denominator = (_D * y2 + 1) % _P
    if denominator == 0:
        return False
    x2 = (y2 - 1) * pow(denominator, -1, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if x * x % _P != x2:
        x = x * _SQRT_MINUS_ONE % _P
    if x * x % _P != x2 or (x == 0 and sign):
        return False
    if x & 1 != sign:
        x = _P - x
    z = 1
    # Projective doublings over public coordinates compute [8]P.
    for _ in range(3):
        a, b, c = x * x % _P, y * y % _P, 2 * z * z % _P
        e, g, h = ((x + y) * (x + y) - a - b) % _P, (b - a) % _P, (-a - b) % _P
        f = (g - c) % _P
        x, y, z = e * f % _P, g * h % _P, f * g % _P
    return x != 0 or y != z


def public_key(seed) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(fixed(seed, 32)).public_key().public_bytes_raw()


def sign(seed, message) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(fixed(seed, 32)).sign(snapshot(message))


def verify(key, message, signature) -> bool:
    key, signature = view(key), view(signature)
    if len(key) != 32 or len(signature) != 64:
        return False
    key, signature = bytes(key), bytes(signature)
    if (int.from_bytes(signature[32:], "little") >= _ORDER
            or not _strict_point(key) or not _strict_point(signature[:32])):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, snapshot(message))
    except InvalidSignature:
        return False
    return True
