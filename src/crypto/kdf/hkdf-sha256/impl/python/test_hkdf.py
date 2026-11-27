import hmac
from importlib import import_module
import unittest

impl = import_module("src.crypto.kdf.hkdf-sha256.impl.python.abc_hkdf_sha256")


def reference(prk, info, length):
    previous = b""
    blocks = []
    for i in range((length + 31) // 32):
        previous = hmac.digest(prk, previous + info + bytes((i + 1,)), "sha256")
        blocks.append(previous)
    return b"".join(blocks)[:length]


class HkdfTests(unittest.TestCase):
    def test_rfc_5869_extract_and_expand(self):
        ikm = bytes([0x0B]) * 22
        salt, info = bytes(range(13)), bytes(range(0xF0, 0xFA))
        prk = impl.extract(salt, ikm)
        self.assertEqual(prk.hex(), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        self.assertEqual(impl.expand(prk, info, 42).hex(), expected)
        self.assertEqual(impl.derive(salt, ikm, info, 42).hex(), expected)
        self.assertEqual(impl.derive(None, ikm, b"", 42).hex(),
                         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
        self.assertEqual(impl.extract(None, ikm), impl.extract(b"", ikm))

    def test_differential_and_counter_255(self):
        info = bytes(range(80))
        for size in (32, 64, 65, 137):
            prk = bytes(range(size))
            for length in (0, 1, 31, 32, 33, 64, 97, 8159, 8160):
                self.assertEqual(impl.expand(prk, info, length), reference(prk, info, length))
        salt, ikm = bytes(range(130)), bytes(range(133))
        prk = hmac.digest(salt, ikm, "sha256")
        self.assertEqual(impl.extract(salt, ikm), prk)
        self.assertEqual(impl.derive(salt, ikm, info, 55), reference(prk, info, 55))

    def test_invalid_types_and_lengths(self):
        for length in (-1, 8161, 2.5, True):
            with self.assertRaises(ValueError):
                impl.expand(bytes(32), b"", length)
        with self.assertRaises(ValueError):
            impl.expand(bytes(31), b"", 0)
        with self.assertRaises(TypeError):
            impl.expand(bytes(32), "not bytes", 0)
