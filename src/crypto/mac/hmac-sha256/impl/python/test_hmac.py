import hmac
from importlib import import_module
import unittest

impl = import_module("src.crypto.mac.hmac-sha256.impl.python.abc_hmac_sha256")


class HmacTests(unittest.TestCase):
    def test_rfc_4231_short_and_long_keys(self):
        cases = (
            (bytes([0x0B]) * 20, b"Hi There",
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (bytes([0xAA]) * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        )
        for key, message, expected in cases:
            self.assertEqual(impl.authenticate(key, message).hex(), expected)

    def test_differential_lengths_and_resets(self):
        for klen in (0, 1, 31, 63, 64, 65, 131):
            key = bytes((11 * i + 7) % 256 for i in range(klen))
            stream = impl.HmacSha256(key)
            for mlen in (0, 1, 55, 64, 130):
                data = bytes((29 * i + 13) % 256 for i in range(mlen))
                expected = hmac.digest(key, data, "sha256")
                self.assertEqual(impl.authenticate(key, data), expected)
                stream.reset()
                stream.update(data[:mlen // 2])
                stream.update(b"")
                stream.update(data[mlen // 2:])
                self.assertEqual(stream.digest(), expected)

    def test_bad_input_and_key_ownership(self):
        key = bytearray(b"key")
        stream = impl.HmacSha256(key)
        key[0] = 0
        stream.update(b"abc")
        expected = hmac.digest(b"key", b"abc", "sha256")
        with self.assertRaises(TypeError):
            stream.update("not bytes")
        self.assertEqual(stream.digest(), expected)
        stream._inner._length = impl.MAX_MESSAGE_BYTES
        before = stream.digest()
        with self.assertRaises(OverflowError):
            stream.update(b"x")
        self.assertEqual(stream.digest(), before)
