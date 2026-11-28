"""RFC 7748 raw X25519 using the cryptography native provider."""
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from src.crypto.providers.python.bytes_input import fixed

_P = (1 << 255) - 19
_MASK = (1 << 255) - 1


def public_key(secret) -> bytes:
    return X25519PrivateKey.from_private_bytes(fixed(secret, 32)).public_key().public_bytes_raw()


def shared_secret(secret, peer) -> bytes | None:
    private = X25519PrivateKey.from_private_bytes(fixed(secret, 32))
    coordinate = int.from_bytes(fixed(peer, 32), "little") & _MASK
    encoded = (coordinate % _P).to_bytes(32, "little")
    try:
        result = private.exchange(X25519PublicKey.from_public_bytes(encoded))
    except ValueError:
        # The fixed-width, reduced input has already passed encoding admission.
        return None
    return result if any(result) else None
