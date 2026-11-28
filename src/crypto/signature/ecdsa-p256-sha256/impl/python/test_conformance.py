import os
from pathlib import Path
import unittest
from unittest.mock import patch

import abc_ecdsa_p256 as api

from src.crypto.providers.python.conformance import test_class

TestProfile = test_class('ecdsa_p256', api)


class TestSigningConfiguration(unittest.TestCase):
    def test_rejects_relative_library(self):
        with self.assertRaisesRegex(ValueError, "must be absolute"):
            api.DeterministicSigner("abc_ecdsa_p256_sha256_c.dll")

    def test_unconfigured_sign_raises_while_public_key_still_works(self):
        with patch.dict(os.environ, {"ABC_ECDSA_P256_LIBRARY": ""}):
            seed = (1).to_bytes(32, "big")
            self.assertEqual(len(api.public_key(seed)), 65)
            with self.assertRaisesRegex(RuntimeError, "ABC_ECDSA_P256_LIBRARY"):
                api.sign(seed, b"message")

    def test_explicit_signer_uses_the_same_signature_format(self):
        library = Path(os.environ["ABC_ECDSA_P256_LIBRARY"])
        signer = api.DeterministicSigner(library)
        seed = (1).to_bytes(32, "big")
        expected = api.sign(seed, b"\x00\x01")
        self.assertEqual(signer.sign(bytearray(seed), memoryview(b"\x00\x01")), expected)
        self.assertTrue(api.verify(api.public_key(seed), b"\x00\x01", expected))

    def test_nonce_exhaustion_is_reported(self):
        signer = object.__new__(api.DeterministicSigner)
        signer._sign = lambda *arguments: 5
        with self.assertRaisesRegex(RuntimeError, "candidate limit was exhausted"):
            signer.sign((1).to_bytes(32, "big"), b"message")
