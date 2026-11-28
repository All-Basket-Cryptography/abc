import hashlib
import sys
import unittest
from array import array
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "keccak-p1600/impl/python"))
from abc_sha3_256 import Sha3_256, sha3_256


class Sha3Tests(unittest.TestCase):
    def test_known_answers(self):
        for message, expected in (
            (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            (b"\xa3" * 200, "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"),
        ):
            self.assertEqual(sha3_256(message).hex(), expected)

    def test_every_split_at_rate_boundaries(self):
        for length in (0, 1, 135, 136, 137, 271, 272, 273, 1000):
            message = bytes(i * 131 % 256 for i in range(length))
            expected = hashlib.sha3_256(message).digest()
            self.assertEqual(sha3_256(message), expected)
            for split in range(length + 1):
                hasher = Sha3_256()
                hasher.update(message[:split])
                self.assertEqual(hasher.digest(), hashlib.sha3_256(message[:split]).digest())
                hasher.update(b"")
                hasher.update(message[split:])
                self.assertEqual(hasher.digest(), expected)

    def test_byte_view_ownership_rejection_and_reset(self):
        message = bytearray(range(250))
        view = memoryview(message)[::2]
        expected = hashlib.sha3_256(view.tobytes()).digest()
        hasher = Sha3_256()
        hasher.update(view)
        message[:] = bytes(len(message))
        with self.assertRaises(TypeError):
            hasher.update(memoryview(array("H", [1, 2, 3])))
        with self.assertRaises(TypeError):
            hasher.update(memoryview(b"abcd").cast("B", (2, 2)))
        self.assertEqual(hasher.digest(), expected)
        hasher.reset()
        self.assertEqual(hasher.digest(), hashlib.sha3_256().digest())
