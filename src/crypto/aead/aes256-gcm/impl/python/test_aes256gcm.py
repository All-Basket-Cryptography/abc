import json
import random
import subprocess
import unittest
from unittest.mock import patch

import abc_aes256gcm as gcm


class GcmTests(unittest.TestCase):
    def test_nist_vectors(self):
        self.assertEqual(gcm.seal_detached(bytes(32), bytes(12), b""),
                         (b"", bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")))
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97f5d3d585")
        data = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        expected = bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        )
        ciphertext, tag = gcm.seal_detached(key, nonce, data, aad)
        self.assertEqual(ciphertext, expected)
        self.assertEqual(tag.hex(), "e097195f4532da895fb917a5a55c6aa0")
        self.assertEqual(gcm.open_detached(key, nonce, ciphertext, tag, aad), data)

    def test_112_independent_openssl_cases(self):
        random_source = random.Random(3804)
        lengths = [(m, a) for m in (0, 1, 15, 16, 17, 31, 32, 33, 129)
                   for a in (0, 1, 15, 16, 17, 65)]
        lengths.extend((i * 41 % 279, i * 37 % 87) for i in range(58))
        inputs = [tuple(map(random_source.randbytes, (32, 12, m, a))) for m, a in lengths]
        script = """
          import { readFileSync } from 'node:fs';
          import { createCipheriv } from 'node:crypto';
          const results = JSON.parse(readFileSync(0, 'utf8')).map(values => {
            const [key, nonce, message, aad] = values.map(value => Buffer.from(value, 'hex'));
            const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
            cipher.setAAD(aad);
            const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
            return [encrypted.toString('hex'), cipher.getAuthTag().toString('hex')];
          });
          console.log(JSON.stringify(results));
        """
        response = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            input=json.dumps([tuple(value.hex() for value in case) for case in inputs]),
            text=True, capture_output=True, check=True, timeout=30,
        )
        for (key, nonce, message, aad), expected in zip(inputs, json.loads(response.stdout), strict=True):
            ciphertext, tag = map(bytes.fromhex, expected)
            self.assertEqual(gcm.seal_detached(key, nonce, message, aad), (ciphertext, tag))
            self.assertEqual(gcm.open_detached(key, nonce, ciphertext, tag, aad), message)

    def test_invalid_tags_never_invoke_payload_decryption(self):
        key, nonce, aad, message = bytes(32), bytes(12), b"header", bytes(range(65))
        ciphertext, tag = gcm.seal_detached(key, nonce, message, aad)
        mutable = bytearray(ciphertext)
        with patch.object(gcm, "_apply", side_effect=AssertionError("premature decrypt")):
            for index in range(16):
                modified = bytearray(tag)
                modified[index] ^= 1
                with self.assertRaises(gcm.InvalidTag):
                    gcm.open_detached(key, nonce, mutable, modified, aad)
            with self.assertRaises(gcm.InvalidTag):
                gcm.open_detached(key, nonce, mutable, tag[:-1], aad)
            with self.assertRaises(gcm.InvalidTag):
                gcm.open_detached(key, nonce, mutable, tag, aad[:-1])
            with self.assertRaises(gcm.InvalidTag):
                gcm.open_detached(key, nonce, mutable[:-1], tag, aad)
        self.assertEqual(mutable, ciphertext)
        with self.assertRaises(ValueError):
            gcm.seal_detached(key, bytes(11), message, aad)

    def test_tag_length_is_checked_before_snapshot(self):
        class InvalidTagView:
            def __len__(self):
                return 17

            def __bytes__(self):
                raise AssertionError("invalid tag snapshot")

        with patch.object(gcm, "_readable", return_value=InvalidTagView()):
            with self.assertRaises(gcm.InvalidTag):
                gcm.open_detached(bytes(32), bytes(12), b"", bytearray(17))
