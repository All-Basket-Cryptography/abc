"""Pure deterministic ML-DSA-65 with explicit OpenSSL signing provider."""
import ctypes as c
from os import environ
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey

from src.crypto.providers.python.bytes_input import fixed, snapshot, view

SEED_BYTES = 32
PUBLIC_KEY_BYTES = 1952
SIGNATURE_BYTES = 3309
_PREFIX = bytes.fromhex("3034020100300b060960864801650304031204228020")


class _Param(c.Structure):
    _fields_ = [("key", c.c_char_p), ("type", c.c_uint), ("data", c.c_void_p),
                ("size", c.c_size_t), ("returned", c.c_size_t)]


class DeterministicSigner:
    """Use a caller-selected libcrypto for the FIPS 204 zero-randomness mode."""

    def __init__(self, library):
        path = Path(library)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("Configure an absolute OpenSSL libcrypto file")
        self._lib = c.CDLL(str(path))

        def bind(name, returns, *arguments):
            function = getattr(self._lib, name)
            function.restype = returns
            function.argtypes = arguments
            return function

        if bind("OpenSSL_version_num", c.c_ulong)() < 0x30500000:
            raise ValueError("Deterministic ML-DSA requires OpenSSL 3.5 or newer")
        self._decode = bind("d2i_AutoPrivateKey", c.c_void_p, c.c_void_p, c.POINTER(c.c_void_p), c.c_long)
        self._free_key = bind("EVP_PKEY_free", None, c.c_void_p)
        self._new_context = bind("EVP_MD_CTX_new", c.c_void_p)
        self._free_context = bind("EVP_MD_CTX_free", None, c.c_void_p)
        self._make_int = bind("OSSL_PARAM_construct_int", _Param, c.c_char_p, c.POINTER(c.c_int))
        self._make_octets = bind("OSSL_PARAM_construct_octet_string", _Param, c.c_char_p, c.c_void_p, c.c_size_t)
        self._end_params = bind("OSSL_PARAM_construct_end", _Param)
        self._init_sign = bind("EVP_DigestSignInit_ex", c.c_int, c.c_void_p, c.c_void_p, c.c_char_p,
                               c.c_void_p, c.c_char_p, c.c_void_p, c.POINTER(_Param))
        self._sign = bind("EVP_DigestSign", c.c_int, c.c_void_p, c.c_void_p, c.POINTER(c.c_size_t),
                          c.c_char_p, c.c_size_t)

    def sign(self, seed, message, context=b"") -> bytes:
        data, domain = snapshot(message), _context(context)
        material = fixed(seed, SEED_BYTES)
        encoded = c.create_string_buffer(len(_PREFIX) + len(material))
        c.memmove(c.addressof(encoded), _PREFIX, len(_PREFIX))
        c.memmove(c.addressof(encoded) + len(_PREFIX), material, len(material))
        cursor = c.c_void_p(c.addressof(encoded))
        try:
            key = self._decode(None, c.byref(cursor), len(encoded))
        finally:
            c.memset(encoded, 0, len(encoded))
        if not key:
            raise RuntimeError("OpenSSL ML-DSA-65 seed import failed")
        try:
            ctx = self._new_context()
            if not ctx:
                raise MemoryError("OpenSSL ML-DSA context allocation failed")
            try:
                flag = c.c_int(1)
                domain_bytes = c.create_string_buffer(domain)
                params = (_Param * 3)(
                    self._make_int(b"deterministic", c.byref(flag)),
                    self._make_octets(b"context-string", domain_bytes, len(domain)),
                    self._end_params(),
                )
                if self._init_sign(ctx, None, None, None, None, key, params) != 1:
                    raise RuntimeError("OpenSSL deterministic ML-DSA initialization failed")
                out = c.create_string_buffer(SIGNATURE_BYTES)
                length = c.c_size_t(len(out))
                if self._sign(ctx, out, c.byref(length), data, len(data)) != 1 or length.value != SIGNATURE_BYTES:
                    raise RuntimeError("OpenSSL deterministic ML-DSA signing failed")
                return out.raw
            finally:
                self._free_context(ctx)
        finally:
            self._free_key(key)


def _context(context) -> bytes:
    wire = view(context)
    if len(wire) > 255:
        raise ValueError("ML-DSA-65 context exceeds 255 bytes")
    return bytes(wire)


def public_key(seed) -> bytes:
    return MLDSA65PrivateKey.from_seed_bytes(fixed(seed, SEED_BYTES)).public_key().public_bytes_raw()


def sign(seed, message, context=b"", *, provider=None) -> bytes:
    if provider is None:
        library = environ.get("ABC_OPENSSL_LIBRARY")
        if not library:
            raise RuntimeError("Set ABC_OPENSSL_LIBRARY or supply a DeterministicSigner")
        provider = DeterministicSigner(library)
    return provider.sign(seed, message, context)


def verify(key, message, signature, context=b"") -> bool:
    key, signature, context = map(view, (key, signature, context))
    if len(key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES or len(context) > 255:
        return False
    try:
        MLDSA65PublicKey.from_public_bytes(bytes(key)).verify(bytes(signature), snapshot(message), bytes(context))
    except (InvalidSignature, ValueError):
        return False
    return True
