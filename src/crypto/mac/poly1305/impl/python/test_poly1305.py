import json
import os
import random
import subprocess
import unittest

from abc_poly1305 import Mac, authenticate


def known_answers():
    def block(first=0, rest=0):
        return bytes([first]) + bytes([rest]) * 15

    zero, one, two, ones = block(), block(1), block(2), block(255, 255)
    r = bytes.fromhex("01000000000000000400000000000000")
    partial = bytes.fromhex("e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000")
    return [
        (bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
         b"Cryptographic Forum Research Group", bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")),
        (two + zero, ones, block(3)),
        (two + ones, two, block(3)),
        (one + zero, ones + block(240, 255) + block(17), block(5)),
        (one + zero, ones + block(251, 254) + block(1, 1), zero),
        (two + zero, block(253, 255), block(250, 255)),
        (r + zero, partial + zero + one, bytes.fromhex("14000000000000005500000000000000")),
        (r + zero, partial + zero, block(19)),
    ]


def polynomial_oracle(key, input_bytes):
    clamped = bytearray(key[:16])
    for offset in (3, 7, 11, 15):
        clamped[offset] %= 16
    for offset in (4, 8, 12):
        clamped[offset] -= clamped[offset] % 4
    r = int.from_bytes(clamped, "little")
    s = int.from_bytes(key[16:], "little")
    terms = [int.from_bytes(input_bytes[i:i + 16] + b"\x01", "little")
             for i in range(0, len(input_bytes), 16)]
    prime = (1 << 130) - 5
    h = sum(term * pow(r, exponent, prime) for exponent, term in enumerate(reversed(terms), 1))
    return ((h % prime + s) % (1 << 128)).to_bytes(16, "little")


NODE_ORACLE = """
const {createCipheriv} = require('node:crypto');
const fs = require('node:fs');
const output = JSON.parse(fs.readFileSync(0, 'utf8')).map(test => {
  const key = Buffer.from(test.key, 'hex'), nonce = Buffer.from(test.nonce, 'hex');
  const aad = Buffer.from(test.aad, 'hex'), data = Buffer.from(test.data, 'hex');
  const block = createCipheriv('chacha20', key, Buffer.concat([Buffer.alloc(4), nonce]));
  const oneTimeKey = Buffer.concat([block.update(Buffer.alloc(32)), block.final()]);
  const aead = createCipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  aead.setAAD(aad);
  const ciphertext = Buffer.concat([aead.update(data), aead.final()]);
  return {key: oneTimeKey.toString('hex'), ciphertext: ciphertext.toString('hex'),
          tag: aead.getAuthTag().toString('hex')};
});
process.stdout.write(JSON.stringify({version: process.versions.openssl, output}));
"""


class Poly1305Test(unittest.TestCase):
    def test_rfc8439_and_streaming(self):
        for key, data, tag in known_answers():
            self.assertEqual(authenticate(key, data), tag)
            for split in range(len(data) + 1):
                state = Mac(key)
                first = bytearray(data[:split])
                state.update(first)
                first[:] = bytes(split)
                state.update(b"")
                state.update(data[split:])
                self.assertEqual(state.finish(), tag)
                self.assertEqual(state.finish(), tag)
                with self.assertRaises(ValueError):
                    state.update(b"")

    def test_independent_polynomial(self):
        rng = random.Random(84391305)
        for i in range(512):
            width = i if i < 96 else rng.randrange(1281)
            key, data = rng.randbytes(32), rng.randbytes(width)
            expected = polynomial_oracle(key, data)
            self.assertEqual(authenticate(key, data), expected)
            state = Mac(key)
            for offset in range(0, width, 23):
                state.update(data[offset:offset + 23])
            self.assertEqual(state.finish(), expected)
        print("512 independent polynomial evaluations and streaming comparisons")

    def test_openssl_aead_tags(self):
        def padded(data):
            return data + bytes(-len(data) % 16)

        rng = random.Random(84392026)
        cases, data_pairs = [], []
        for i in range(96):
            widths = (0, 1, 15, 16, 17, 63, 64, 65)
            data_len, aad_len = rng.randrange(513), rng.randrange(193)
            if i < len(widths) ** 2:
                data_len, aad_len = widths[i // len(widths)], widths[i % len(widths)]
            key, nonce = rng.randbytes(32), rng.randbytes(12)
            aad, data = rng.randbytes(aad_len), rng.randbytes(data_len)
            cases.append(dict(key=key.hex(), nonce=nonce.hex(), aad=aad.hex(), data=data.hex()))
            data_pairs.append((aad, data_len))
        wire = subprocess.run(["node", "-e", NODE_ORACLE], input=json.dumps(cases).encode(),
                              capture_output=True, check=True, timeout=60)
        reply = json.loads(wire.stdout)
        self.assertEqual(len(reply["output"]), len(data_pairs))
        for result, (aad, width) in zip(reply["output"], data_pairs):
            key = bytes.fromhex(result["key"])
            ciphertext = bytes.fromhex(result["ciphertext"])
            self.assertEqual(len(ciphertext), width)
            message = (padded(aad) + padded(ciphertext) + len(aad).to_bytes(8, "little")
                       + width.to_bytes(8, "little"))
            self.assertEqual(authenticate(key, message).hex(), result["tag"])
        print(f"{len(data_pairs)} independent OpenSSL {reply['version']} AEAD tags")

    def test_optional_direct_openssl(self):
        provider = os.environ.get("ABC_OPENSSL")
        if not provider:
            self.skipTest("Set ABC_OPENSSL to enable the direct EVP-MAC oracle")
        rng = random.Random(1305)
        for size in (0, 1, 15, 16, 17, 64, 255, 256, *range(80, 104)):
            key, data = rng.randbytes(32), rng.randbytes(size)
            result = subprocess.run([provider, "mac", "-macopt", "hexkey:" + key.hex(), "POLY1305"],
                                    input=data, check=True, capture_output=True, timeout=20)
            self.assertEqual(authenticate(key, data), bytes.fromhex(result.stdout.decode()))
        version = subprocess.check_output([provider, "version"], timeout=20).decode().strip()
        print(f"32 independent direct Poly1305 MACs via {version}")

    def test_empty_and_validation(self):
        key = bytearray(bytes(range(32)))
        state = Mac(key)
        key[:] = bytes(32)
        with self.assertRaises(TypeError):
            state.update(object())
        self.assertEqual(state.finish(), bytes(range(16, 32)))
        with self.assertRaises(ValueError):
            Mac(bytes(31))


if __name__ == "__main__":
    unittest.main()
