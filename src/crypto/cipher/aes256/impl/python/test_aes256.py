import json
import random
import subprocess
import unittest

from abc_aes256 import Aes256


class Aes256Tests(unittest.TestCase):
    def test_published_vectors(self):
        vectors = [
            (bytes(range(32)), "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
            (bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
             "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"),
        ]
        for key, plaintext, ciphertext in vectors:
            aes = Aes256(key)
            self.assertEqual(aes.encrypt(bytes.fromhex(plaintext)).hex(), ciphertext)
            self.assertEqual(aes.decrypt(bytes.fromhex(ciphertext)).hex(), plaintext)

    def test_independent_openssl_encrypt_and_decrypt(self):
        random_source = random.Random(197)
        inputs = [(random_source.randbytes(32), random_source.randbytes(16)) for _ in range(256)]
        script = """
          import { readFileSync } from 'node:fs';
          import { createCipheriv, createDecipheriv } from 'node:crypto';
          const results=JSON.parse(readFileSync(0,'utf8')).map(([key, block]) => {
            const k=Buffer.from(key,'hex'), b=Buffer.from(block,'hex');
            const run=f=>{const c=f('aes-256-ecb',k,null).setAutoPadding(false);
              return Buffer.concat([c.update(b),c.final()]).toString('hex');};
            return [run(createCipheriv),run(createDecipheriv)];
          });
          console.log(JSON.stringify(results));
        """
        response = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            input=json.dumps([(key.hex(), block.hex()) for key, block in inputs]),
            text=True, capture_output=True, check=True, timeout=30,
        )
        for (key, block), (encrypted, decrypted) in zip(inputs, json.loads(response.stdout), strict=True):
            cipher = Aes256(key)
            self.assertEqual(cipher.encrypt(block).hex(), encrypted)
            self.assertEqual(cipher.decrypt(block).hex(), decrypted)
            self.assertEqual(cipher.decrypt(bytes.fromhex(encrypted)), block)

    def test_key_ownership_and_rejection(self):
        key = bytearray(range(32))
        aes = Aes256(memoryview(key))
        block = bytearray(range(16))
        expected = aes.encrypt(block)
        key[:] = bytes(32)
        self.assertEqual(aes.encrypt(block), expected)
        self.assertEqual(block, bytearray(range(16)))
        with self.assertRaises(ValueError):
            Aes256(bytes(31))
        for operation in (aes.encrypt, aes.decrypt):
            with self.assertRaises(ValueError):
                operation(bytes(15))
