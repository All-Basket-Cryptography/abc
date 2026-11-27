import json
import random
import subprocess
import unittest

from abc_chacha20 import block, fits_counter, xor, xor_into


PLAINTEXT = bytes.fromhex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e")

ORACLE = """
const {createCipheriv} = require('node:crypto');
const fs = require('node:fs');
const output = JSON.parse(fs.readFileSync(0, 'utf8')).map(test => {
  const iv = Buffer.alloc(16);
  iv.writeUInt32LE(test.counter);
  Buffer.from(test.nonce, 'hex').copy(iv, 4);
  const cipher = createCipheriv('chacha20', Buffer.from(test.key, 'hex'), iv);
  const wire = Buffer.concat([cipher.update(Buffer.from(test.data, 'hex')), cipher.final()]);
  return wire.toString('hex');
});
process.stdout.write(JSON.stringify({version: process.versions.openssl, output}));
"""


class ChaCha20Test(unittest.TestCase):
    def test_rfc8439(self):
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        self.assertEqual(block(key, nonce, 1).hex(),
                         "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                         "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
        nonce = bytes.fromhex("000000000000004a00000000")
        cipher = xor(key, nonce, 1, PLAINTEXT)
        self.assertEqual(cipher.hex(),
                         "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                         "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                         "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                         "5af90bbf74a35be6b40b8eedf2785e42874d")
        self.assertEqual(xor(key, nonce, 1, cipher), PLAINTEXT)

    def test_counter_and_validation(self):
        key, nonce = bytes(32), bytes(12)
        final = (1 << 32) - 1
        for counter in (0, 1, final - 1, final):
            maximum = ((1 << 32) - counter) * 64
            self.assertTrue(fits_counter(0, counter))
            self.assertTrue(fits_counter(maximum, counter))
            self.assertFalse(fits_counter(maximum + 1, counter))
        self.assertFalse(fits_counter(-1, 0))
        self.assertFalse(fits_counter(0, -1))
        self.assertFalse(fits_counter(0, 1 << 32))
        self.assertEqual(xor(key, nonce, final, bytes(64)), block(key, nonce, final))
        self.assertEqual(xor(key, nonce, final, b""), b"")

        output = bytearray(b"x" * 65)
        with self.assertRaises(ValueError):
            xor_into(key, nonce, final, bytes(65), output)
        with self.assertRaises(ValueError):
            xor_into(key, nonce, 1, bytes(66), output)
        with self.assertRaises(ValueError):
            xor_into(key[:-1], nonce, 1, b"a", output)
        with self.assertRaises(ValueError):
            xor_into(key, nonce[:-1], 1, b"a", output)
        with self.assertRaises(TypeError):
            xor_into(key, nonce, 1, b"a", bytes(output))
        self.assertEqual(output, b"x" * 65)

    def test_overlap_and_block_aligned_split(self):
        key, nonce = bytes(range(32)), bytes(range(12))
        message = bytes(range(219))
        counter = 11
        expected = xor(key, nonce, counter, message)
        self.assertEqual(xor(key, nonce, counter, message[:128])
                         + xor(key, nonce, counter + 2, message[128:]), expected)
        for source, destination in ((2, 9), (9, 2), (2, 2)):
            memory = bytearray(b"v" * (len(message) + 20))
            memory[source:source + len(message)] = message
            saved = bytes(memory[destination + len(message):])
            view = memoryview(memory)
            xor_into(key, nonce, counter, view[source:source + len(message)], view[destination:])
            self.assertEqual(memory[destination:destination + len(message)], expected)
            self.assertEqual(memory[destination + len(message):], saved)

    def test_openssl(self):
        rng = random.Random(843920)
        sizes = [0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257, 64]
        cases, expected = [], []
        for i in range(144):
            width = sizes[i] if i < len(sizes) else rng.randrange(1153)
            counter = (1 << 32) - 1 if i == len(sizes) - 1 else rng.randrange(4096)
            key, nonce, data = rng.randbytes(32), rng.randbytes(12), rng.randbytes(width)
            cases.append(dict(key=key.hex(), nonce=nonce.hex(), counter=counter, data=data.hex()))
            expected.append(xor(key, nonce, counter, data).hex())
        wire = subprocess.run(["node", "-e", ORACLE], input=json.dumps(cases).encode(),
                              capture_output=True, check=True, timeout=60)
        answer = json.loads(wire.stdout)
        self.assertEqual(answer["output"], expected)
        print(f"{len(expected)} independent OpenSSL {answer['version']} ciphertexts")


if __name__ == "__main__":
    unittest.main()
