"""Independent ML-KEM-768 oracle using the OpenSSL 3.5.4 provider ABI."""

from contextlib import contextmanager
import ctypes as ffi
import os


PTR = ffi.c_void_p
SIZE = ffi.c_size_t


class Parameter(ffi.Structure):
    _fields_ = [("key", ffi.c_char_p), ("data_type", ffi.c_uint), ("data", PTR), ("data_size", SIZE),
                ("return_size", SIZE)]


def octet_string(name, value):
    # OSSL_PARAM_OCTET_STRING and OSSL_PARAM_UNMODIFIED from OpenSSL core.h.
    value = (ffi.c_ubyte * len(value)).from_buffer_copy(value)
    parameters = (Parameter * 2)(Parameter(name, 5, ffi.cast(value, PTR), len(value), SIZE(-1).value), Parameter())
    return parameters, value


def require(result, operation):
    if result != 1:
        raise RuntimeError(f"OpenSSL ML-KEM {operation} failed")


class Oracle:
    def __init__(self, library):
        with os.add_dll_directory(str(library.parent)):
            self.library = ffi.CDLL(str(library))
        self.version = self.bind("OpenSSL_version", ffi.c_char_p, ffi.c_int)(0).decode("ascii")
        if not self.version.startswith("OpenSSL 3.5.4 "):
            raise ValueError(f"Expected OpenSSL 3.5.4, observed {self.version}")

        parameter = ffi.POINTER(Parameter)
        size_pointer = ffi.POINTER(SIZE)
        self.ctx_from_name = self.bind("EVP_PKEY_CTX_new_from_name", PTR, PTR, ffi.c_char_p, ffi.c_char_p)
        self.ctx_from_key = self.bind("EVP_PKEY_CTX_new_from_pkey", PTR, PTR, PTR, ffi.c_char_p)
        self.ctx_free = self.bind("EVP_PKEY_CTX_free", None, PTR)
        self.key_free = self.bind("EVP_PKEY_free", None, PTR)
        self.keygen_init = self.bind("EVP_PKEY_keygen_init", ffi.c_int, PTR)
        self.set_params = self.bind("EVP_PKEY_CTX_set_params", ffi.c_int, PTR, parameter)
        self.generate = self.bind("EVP_PKEY_generate", ffi.c_int, PTR, ffi.POINTER(PTR))
        self.get_param = self.bind("EVP_PKEY_get_octet_string_param", ffi.c_int, PTR, ffi.c_char_p, PTR, SIZE, size_pointer)
        self.encap_init = self.bind("EVP_PKEY_encapsulate_init", ffi.c_int, PTR, parameter)
        self.encap = self.bind("EVP_PKEY_encapsulate", ffi.c_int, PTR, PTR, size_pointer, PTR, size_pointer)
        self.decap_init = self.bind("EVP_PKEY_decapsulate_init", ffi.c_int, PTR, parameter)
        self.decap = self.bind("EVP_PKEY_decapsulate", ffi.c_int, PTR, PTR, size_pointer, PTR, SIZE)

    def bind(self, name, result, *args):
        function = getattr(self.library, name)
        function.restype = result
        function.argtypes = args
        return function

    @contextmanager
    def keypair(self, seed):
        ctx = self.ctx_from_name(None, b"ML-KEM-768", b"provider=default")
        if not ctx:
            raise RuntimeError("OpenSSL ML-KEM-768 context creation failed")
        key = PTR()
        try:
            require(self.keygen_init(ctx), "keygen init")
            params, seed_buffer = octet_string(b"seed", seed)
            require(self.set_params(ctx, params), "set seed")
            require(self.generate(ctx, ffi.byref(key)), "keygen")
            yield key
        finally:
            self.key_free(key)
            self.ctx_free(ctx)

    def raw(self, key, name, length):
        output = (ffi.c_ubyte * length)()
        received = SIZE()
        require(self.get_param(key, name, output, length, ffi.byref(received)), "export raw key")
        if received.value != length:
            raise RuntimeError("OpenSSL ML-KEM returned an unexpected raw key length")
        return bytes(output)

    def encapsulate(self, key, message):
        ctx = self.ctx_from_key(None, key, None)
        if not ctx:
            raise RuntimeError("OpenSSL ML-KEM encapsulation context creation failed")
        try:
            params, message_buffer = octet_string(b"ikme", message)
            require(self.encap_init(ctx, params), "encapsulation init")
            ciphertext = (ffi.c_ubyte * 1088)()
            shared = (ffi.c_ubyte * 32)()
            ct_len, shared_len = SIZE(len(ciphertext)), SIZE(len(shared))
            require(self.encap(ctx, ciphertext, ffi.byref(ct_len), shared, ffi.byref(shared_len)), "encapsulation")
            if ct_len.value != len(ciphertext) or shared_len.value != len(shared):
                raise RuntimeError("OpenSSL ML-KEM returned an unexpected encapsulation length")
            return bytes(ciphertext), bytes(shared)
        finally:
            self.ctx_free(ctx)

    def decapsulate(self, key, ciphertext):
        ctx = self.ctx_from_key(None, key, None)
        if not ctx:
            raise RuntimeError("OpenSSL ML-KEM decapsulation context creation failed")
        try:
            require(self.decap_init(ctx, None), "decapsulation init")
            cipher_buffer = (ffi.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
            shared = (ffi.c_ubyte * 32)()
            shared_len = SIZE(len(shared))
            require(self.decap(ctx, shared, ffi.byref(shared_len), cipher_buffer, len(cipher_buffer)), "decapsulation")
            if shared_len.value != len(shared):
                raise RuntimeError("OpenSSL ML-KEM returned an unexpected decapsulation length")
            return bytes(shared)
        finally:
            self.ctx_free(ctx)
