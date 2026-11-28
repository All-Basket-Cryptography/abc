"""FIPS 203 ML-KEM-768 using 64-byte seed private keys and native OpenSSL."""
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey

from src.crypto.providers.python.bytes_input import fixed

SEED_BYTES = 64
PUBLIC_KEY_BYTES = 1184
CIPHERTEXT_BYTES = 1088


def public_key(seed) -> bytes:
    private = MLKEM768PrivateKey.from_seed_bytes(fixed(seed, SEED_BYTES))
    return private.public_key().public_bytes_raw()


def encapsulate(key) -> tuple[bytes, bytes]:
    public = MLKEM768PublicKey.from_public_bytes(fixed(key, PUBLIC_KEY_BYTES))
    shared, ciphertext = public.encapsulate()
    return ciphertext, shared


def decapsulate(seed, ciphertext) -> bytes:
    wire = fixed(ciphertext, CIPHERTEXT_BYTES)
    private = MLKEM768PrivateKey.from_seed_bytes(fixed(seed, SEED_BYTES))
    return private.decapsulate(wire)
