import hashlib
import sys
import unittest
from array import array
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "keccak-p1600/impl/python"))
from abc_shake256 import Shake256, shake256


class ShakeTests(unittest.TestCase):
    def test_known_answers(self):
        for message, expected in (
            (b"", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
            (b"abc", "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"),
        ):
            self.assertEqual(shake256(message, 32).hex(), expected)

    def test_every_split_at_rate_boundaries(self):
        for length in (0, 1, 135, 136, 137, 271, 272, 273, 1000):
            message = bytes(i * 131 % 256 for i in range(length))
            expected = hashlib.shake_256(message).digest(409)
            self.assertEqual(shake256(message, 409), expected)
            for split in range(length + 1):
                absorber = Shake256()
                absorber.update(message[:split])
                absorber.update(b"")
                absorber.update(message[split:])
                reader = absorber.finalize()
                chunks = []
                for count in (0, 1, 134, 1, 136, 137):
                    chunks.append(reader.read(count))
                self.assertEqual(b"".join(chunks), expected)

    def test_reader_validation_and_independent_snapshots(self):
        absorber = Shake256()
        message = bytearray(range(250))
        view = memoryview(message)[::2]
        expected = hashlib.shake_256(view.tobytes()).digest(409)
        absorber.update(view)
        first, second = absorber.finalize(), absorber.finalize()
        message[:] = bytes(len(message))
        absorber.reset()
        absorber.update(b"other message")
        with self.assertRaises(ValueError):
            first.read(-1)
        with self.assertRaises(TypeError):
            first.read(1.5)
        with self.assertRaises(TypeError):
            first.readinto(b"read only")
        with self.assertRaises(TypeError):
            first.readinto(memoryview(bytearray(8))[::2])
        with self.assertRaises(TypeError):
            first.readinto(memoryview(array("H", [1, 2])))
        result = bytearray(415)
        self.assertEqual(first.readinto(memoryview(result)[3:-3]), 409)
        self.assertEqual(result, b"\0" * 3 + expected + b"\0" * 3)
        self.assertEqual(second.read(409), expected)
