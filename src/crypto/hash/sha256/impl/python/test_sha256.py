import array
import hashlib
import random
import unittest

from abc_sha256 import MAX_MESSAGE_BYTES, Sha256, sha256


class Sha256Tests(unittest.TestCase):
    def test_known_answers(self):
        for data, expected in (
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ):
            with self.subTest(data=data):
                self.assertEqual(sha256(data).hex(), expected)

    def test_all_splits_near_padding_and_block_edges(self):
        for size in (0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129):
            data = bytes(range(size))
            expected = hashlib.sha256(data).digest()
            for split in range(size + 1):
                context = Sha256()
                context.update(data[:split])
                context.update(b"")
                context.update(data[split:])
                self.assertEqual(context.digest(), expected, (size, split))

    def test_deterministic_binary_inputs(self):
        rng = random.Random(20261128)
        for _ in range(128):
            data = rng.randbytes(rng.randrange(2049))
            expected = hashlib.sha256(data).digest()
            self.assertEqual(sha256(data), expected)
            context = Sha256()
            chunk = rng.randrange(1, 97)
            for start in range(0, len(data), chunk):
                context.update(data[start:start + chunk])
            self.assertEqual(context.digest(), expected)

    def test_buffers_snapshot_and_reset(self):
        source = bytearray(b"a-b-c-")
        context = Sha256()
        context.update(memoryview(source)[::2])
        source[0] = ord("z")
        first = hashlib.sha256(b"abc").digest()
        self.assertEqual(context.digest(), first)
        self.assertEqual(context.digest(), first)
        with self.assertRaises(TypeError):
            context.update(memoryview(array.array("H", [42])))
        self.assertEqual(context.digest(), first)
        context.update(b"def")
        self.assertEqual(context.digest(), hashlib.sha256(b"abcdef").digest())
        context.reset()
        self.assertEqual(context.digest(), hashlib.sha256().digest())

    def test_overflow_does_not_change_state(self):
        context = Sha256()
        context.update(bytes(62))
        context._length = MAX_MESSAGE_BYTES - 1
        context.update(b"x")
        before = (context._length, bytes(context._tail), context._state.copy(), context.digest())
        with self.assertRaises(OverflowError):
            context.update(b"y")
        self.assertEqual((context._length, bytes(context._tail), context._state, context.digest()), before)
        context.update(b"")
        self.assertEqual(context.digest(), before[-1])


if __name__ == "__main__":
    unittest.main()
