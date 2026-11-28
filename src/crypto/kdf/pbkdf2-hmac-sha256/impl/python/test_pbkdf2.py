from hashlib import pbkdf2_hmac
from importlib import import_module
import unittest

impl = import_module("src.crypto.kdf.pbkdf2-hmac-sha256.impl.python.abc_pbkdf2_sha256")


class Pbkdf2Tests(unittest.TestCase):
    def test_rfc_7914_vector(self):
        expected = ("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                    "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
        self.assertEqual(impl.derive(b"passwd", b"salt", 1, 64).hex(), expected)

    def test_differential(self):
        for key, salt in ((b"", b""), (b"pass\0word", b"sa\0lt"),
                          (bytes(range(65)), b"salt"), (bytes(range(137)), bytes(range(60)))):
            for iterations in (1, 2, 7):
                for length in (1, 31, 32, 33, 64, 65):
                    self.assertEqual(impl.derive(key, salt, iterations, length),
                                     pbkdf2_hmac("sha256", key, salt, iterations, length))
        self.assertEqual(impl.derive(b"k", b"s", 1, 8193), pbkdf2_hmac("sha256", b"k", b"s", 1, 8193))

    def test_bad_parameters(self):
        for count in (0, -1, True, 1.5, impl.MAX_ITERATIONS + 1):
            with self.assertRaises(ValueError):
                impl.derive(b"p", b"s", count, 1)
        for length in (0, -1, False, 1.5, impl.MAX_OUTPUT_BYTES + 1):
            with self.assertRaises(ValueError):
                impl.derive(b"p", b"s", 1, length)
        with self.assertRaises(TypeError):
            impl.derive(b"p", "not bytes", 1, 4)
