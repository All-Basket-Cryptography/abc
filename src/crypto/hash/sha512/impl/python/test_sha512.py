import hashlib
import unittest
from array import array

from abc_sha512 import MAX_MESSAGE_BYTES, Sha512, sha512


class Sha512Tests(unittest.TestCase):
    def test_known_answers(self):
        for message, expected in [
            (b"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                  "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            (b"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        ]:
            self.assertEqual(sha512(message).hex(), expected)

    def test_provider_and_all_boundary_splits(self):
        data = bytes((index * index + 17) % 256 for index in range(1025))
        for length in (0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 257, 1025):
            message = data[:length]
            expected = hashlib.sha512(message).digest()
            self.assertEqual(sha512(message), expected)
            for split in range(length + 1):
                context = Sha512()
                mutable = bytearray(message[:split])
                context.update(mutable)
                mutable[:] = bytes(split)
                self.assertEqual(context.digest(), hashlib.sha512(message[:split]).digest())
                context.update(message[split:])
                self.assertEqual(context.digest(), expected)
                context.reset()
                self.assertEqual(context.digest(), hashlib.sha512().digest())

    def test_buffer_formats_and_rejection_preserve_state(self):
        buffer = memoryview(bytearray(range(32)))[::-2]
        context = Sha512()
        context.update(buffer)
        expected = hashlib.sha512(buffer.tobytes()).digest()
        self.assertEqual(context.digest(), expected)
        with self.assertRaises(TypeError):
            context.update(memoryview(array("H", [1, 2])))
        with self.assertRaises(TypeError):
            context.update(memoryview(bytearray(9)).cast("B", (3, 3)))
        self.assertEqual(context.digest(), expected)

    def test_128_bit_length_boundary(self):
        context = Sha512()
        context._length = MAX_MESSAGE_BYTES - 1
        context._tail = bytearray(126)
        context.update(b"a")
        expected = context.digest()
        with self.assertRaises(OverflowError):
            context.update(b"b")
        context.update(b"")
        self.assertEqual(context.digest(), expected)
