import json
import random
import subprocess
import unittest
from unittest.mock import patch

import abc_chacha20_poly1305 as aead


_NODE_ORACLE = """
const {createCipheriv, createDecipheriv} = require('node:crypto');
const fs = require('node:fs');
const decode = value => Buffer.from(value, 'hex');
const output = JSON.parse(fs.readFileSync(0, 'utf8')).map(test => {
  const key = decode(test.key), nonce = decode(test.nonce), aad = decode(test.aad);
  const plaintext = decode(test.plaintext);
  const seal = createCipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  seal.setAAD(aad);
  const ciphertext = Buffer.concat([seal.update(plaintext), seal.final()]);
  const open = createDecipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  open.setAAD(aad);
  open.setAuthTag(decode(test.tag));
  if (!Buffer.concat([open.update(decode(test.ciphertext)), open.final()]).equals(plaintext))
    throw Error('Python ciphertext did not open');
  return {ciphertext: ciphertext.toString('hex'), tag: seal.getAuthTag().toString('hex')};
});
process.stdout.write(JSON.stringify({version: process.versions.openssl, output}));
"""


class ChaCha20Poly1305Test(unittest.TestCase):
    def test_rfc8439_example(self):
        key = bytes(range(0x80, 0xa0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = bytes.fromhex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
            "637265656e20776f756c642062652069742e")
        ciphertext, tag = aead.seal_detached(key, nonce, plaintext, aad)
        self.assertEqual(ciphertext.hex(),
                         "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                         "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                         "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                         "3ff4def08e4b7a9de576d26586cec64b6116")
        self.assertEqual(tag.hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(aead.open_detached(key, nonce, ciphertext, tag, aad), plaintext)

    def test_rejection_without_decryption_or_output(self):
        key, aad = bytes(range(32)), b"associated data"
        for width in (0, 1, 15, 16, 17, 64, 65, 137):
            nonce = width.to_bytes(12, "little")
            message = bytes(range(width))
            ciphertext, tag = aead.seal_detached(key, nonce, message, aad)
            failures = [(ciphertext, tag[:-1], aad), (ciphertext, tag + b"\x00", aad),
                        (ciphertext, tag, b"wrong associated data")]
            if ciphertext:
                failures.append((bytes([ciphertext[0] ^ 1]) + ciphertext[1:], tag, aad))
            for index in range(len(tag)):
                wrong = bytearray(tag)
                wrong[index] ^= 1
                failures.append((ciphertext, wrong, aad))
            with patch.object(aead._chacha, "xor") as decrypt:
                for damaged, authenticator, context in failures:
                    destination = bytearray(damaged + b"sentinel")
                    alias = memoryview(destination)[:width]
                    with self.assertRaises(aead.InvalidTag):
                        aead.open_into(key, nonce, alias, authenticator, destination, context)
                    self.assertEqual(destination, damaged + b"sentinel")
                decrypt.assert_not_called()

    def test_uses_the_snapshot_that_passed_authentication(self):
        key = bytearray(range(32))
        nonce = bytearray(range(12))
        aad = bytearray(b"context")
        original = bytes(range(147))
        ciphertext, tag = aead.seal_detached(key, nonce, original, aad)
        mutable = bytearray(ciphertext)
        reference = aead.compare_digest

        def compare_then_mutate(a, b):
            result = reference(a, b)
            key[0] ^= 1
            nonce[0] ^= 1
            aad[0] ^= 1
            mutable[0] ^= 1
            return result

        with patch.object(aead, "compare_digest", side_effect=compare_then_mutate):
            self.assertEqual(aead.open_detached(key, nonce, mutable, tag, aad), original)

    def test_overlapping_buffers_and_preflight(self):
        key, nonce = bytes(32), bytes(12)
        memory = bytearray(range(149))
        view = memoryview(memory)
        plaintext, aad = bytes(view[:80]), bytes(view[12:35])
        expect, tag = aead.seal_detached(key, nonce, plaintext, aad)
        trailing = bytes(view[90:])
        self.assertEqual(aead.seal_into(key, nonce, view[:80], view[10:], view[12:35]), tag)
        self.assertEqual(view[10:90], expect)
        self.assertEqual(view[90:], trailing)
        view[:len(aad)] = aad
        view[30:110] = expect
        aead.open_into(key, nonce, view[30:110], tag, view[4:], view[:len(aad)])
        self.assertEqual(view[4:84], plaintext)

        saved = bytes(memory)
        with self.assertRaises(ValueError):
            aead.seal_into(key, nonce, plaintext, view[:79], aad)
        with self.assertRaises(ValueError):
            aead.seal_into(key[:-1], nonce, plaintext, view, aad)
        with self.assertRaises(TypeError):
            aead.open_into(key, nonce, expect, tag, bytes(memory), aad)
        self.assertEqual(memory, saved)
        aead._check_lengths(((1 << 32) - 1) * 64, (1 << 64) - 1)
        with self.assertRaises(ValueError):
            aead._check_lengths(((1 << 32) - 1) * 64 + 1, 0)
        with self.assertRaises(ValueError):
            aead._check_lengths(0, 1 << 64)

    def test_openssl_interoperability(self):
        rng = random.Random(8439)
        sizes = (0, 1, 15, 16, 17, 63, 64, 65)
        cases, inputs = [], []
        for index in range(174):
            width, aad_width = rng.randrange(1025), rng.randrange(145)
            if index < len(sizes) ** 2:
                width, aad_width = sizes[index // len(sizes)], sizes[index % len(sizes)]
            key, nonce = rng.randbytes(32), rng.randbytes(12)
            plaintext, aad = rng.randbytes(width), rng.randbytes(aad_width)
            ciphertext, tag = aead.seal_detached(key, nonce, plaintext, aad)
            cases.append(dict(key=key.hex(), nonce=nonce.hex(), plaintext=plaintext.hex(),
                              aad=aad.hex(), ciphertext=ciphertext.hex(), tag=tag.hex()))
            inputs.append((key, nonce, plaintext, aad))
        wire = subprocess.run(["node", "-e", _NODE_ORACLE], input=json.dumps(cases).encode(),
                              capture_output=True, check=True, timeout=60)
        reply = json.loads(wire.stdout)
        self.assertEqual(len(reply["output"]), len(cases))
        for expected, case, (key, nonce, plaintext, aad) in zip(reply["output"], cases, inputs):
            self.assertEqual(expected["ciphertext"], case["ciphertext"])
            self.assertEqual(expected["tag"], case["tag"])
            ciphertext, tag = bytes.fromhex(expected["ciphertext"]), bytes.fromhex(expected["tag"])
            self.assertEqual(aead.open_detached(key, nonce, ciphertext, tag, aad), plaintext)
        print(f"{len(cases)} bidirectional OpenSSL {reply['version']} cases")


if __name__ == "__main__":
    unittest.main()
