import hashlib
from array import array
import unittest

from abc_blake2b import Blake2b, MAX_MESSAGE_BYTES, blake2b


def pattern(length):
    return bytes((37 * i + 11) % 256 for i in range(length))


class Blake2bTests(unittest.TestCase):
    def test_rfc7693_and_digest_size_binding(self):
        full = blake2b(b"abc")
        self.assertEqual(full.hex(),
                         "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d"
                         "87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
        self.assertNotEqual(full[:32], blake2b(b"abc", 32))

    def test_all_digest_sizes_and_final_block_splits(self):
        for length in (0, 1, 127, 128, 129, 255, 256, 257, 1000):
            message = pattern(length)
            for size in range(1, 65):
                expected = hashlib.blake2b(message, digest_size=size).digest()
                self.assertEqual(blake2b(message, size), expected)
                if size not in (1, 31, 64):
                    continue
                for split in range(length + 1):
                    hasher = Blake2b(size)
                    hasher.update(message[:split])
                    hasher.update(b"")
                    hasher.update(message[split:])
                    self.assertEqual(hasher.digest(), expected)

    def test_snapshot_reset_and_error_states(self):
        for invalid in (-1, 0, 65):
            with self.assertRaises(ValueError):
                Blake2b(invalid)
        with self.assertRaises(TypeError):
            Blake2b(32.0)

        caller = bytearray(pattern(256))
        pending = bytes(caller[::2])
        hasher = Blake2b(31)
        hasher.update(memoryview(caller)[::2])
        caller[:] = bytes(len(caller))
        expected = hashlib.blake2b(pending, digest_size=31).digest()
        self.assertEqual(hasher.digest(), expected)
        self.assertEqual(hasher.digest(), expected)
        for bad in (memoryview(array("H", [1])), memoryview(b"abcx").cast("B", (2, 2))):
            with self.assertRaises(TypeError):
                hasher.update(bad)
        self.assertEqual(hasher.digest(), expected)
        hasher.update(b"f")
        self.assertEqual(hasher.digest(), hashlib.blake2b(pending + b"f", digest_size=31).digest())
        hasher.reset()
        self.assertEqual(hasher.digest(), hashlib.blake2b(digest_size=31).digest())

    def test_counter_preserves_state_on_rejection(self):
        hasher = Blake2b(1)
        hasher._length = MAX_MESSAGE_BYTES - 1
        hasher._tail = bytearray(126)
        hasher.update(b"x")
        snapshot = hasher.digest()
        with self.assertRaises(OverflowError):
            hasher.update(b"y")
        hasher.update(b"")
        self.assertEqual(hasher._length, MAX_MESSAGE_BYTES)
        self.assertEqual(hasher.digest(), snapshot)
