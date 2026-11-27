import hashlib
from random import Random
from sys import maxsize
import unittest

from abc_scrypt import derive, workspace_size


class ScryptTests(unittest.TestCase):
    def test_rfc7914(self):
        result = derive(b"", b"", cost=16, block_size=1, parallel=1,
                        length=64, memory_limit=4096)
        self.assertEqual(result.hex(),
                         "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
                         "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")

    def test_provider_comparisons(self):
        rng = Random(7914)
        for n in (2, 16, 32):
            for r in (1, 2, 4):
                for p in (1, 2, 3):
                    for length in (1, 33, 64):
                        password = rng.randbytes(rng.choice((0, 31, 64, 65, 133, 513)))
                        salt = rng.randbytes(rng.choice((0, 16, 64, 129)))
                        required = workspace_size(cost=n, block_size=r, parallel=p)
                        expected = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=length)
                        self.assertEqual(derive(password, salt, cost=n, block_size=r, parallel=p,
                                                length=length, memory_limit=required + length), expected)

    def test_parameters_and_budget(self):
        for n, r, p in [(1, 1, 1), (3, 1, 1), (16, 0, 1), (16, 1, 0), (1 << 16, 1, 1)]:
            with self.assertRaises(ValueError):
                workspace_size(cost=n, block_size=r, parallel=p)
        with self.assertRaises(TypeError):
            workspace_size(cost=16, block_size=1, parallel=True)
        with self.assertRaises(OverflowError):
            workspace_size(cost=1 << (maxsize.bit_length() - 8), block_size=4, parallel=1)
        required = workspace_size(cost=16, block_size=2, parallel=3)
        self.assertEqual(required, 20 * 2 * 128)
        with self.assertRaisesRegex(ValueError, "memory budget"):
            derive(b"password", b"salt", cost=16, block_size=2, parallel=3, length=32,
                   memory_limit=required + 31)
