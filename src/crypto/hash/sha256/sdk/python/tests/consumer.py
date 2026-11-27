"""Run as an independent consumer of an installed ABC research wheel."""

from array import array
from copy import copy, deepcopy
import gc
from hashlib import sha256
from importlib import metadata
from pathlib import Path
import sys
import unittest
from weakref import ref

import abc_crypto
from abc_crypto import _native


class WheelConsumerTests(unittest.TestCase):
    def test_installed_metadata_and_native_backend(self):
        distribution = metadata.distribution("abc-crypto-research")
        self.assertEqual(distribution.version, "0.1.0")
        licenses = distribution.metadata.get_all("License-File")
        self.assertIn("third-party-licenses/pyo3-0.23.5/LICENSE-MIT", licenses)
        filenames = [path.as_posix() for path in distribution.files]
        for license_file in licenses:
            self.assertTrue(any(name.endswith(f".dist-info/licenses/{license_file}") for name in filenames))
        root = Path(abc_crypto.__file__).resolve().parent
        self.assertTrue(root.is_relative_to(Path(sys.prefix).resolve()))
        self.assertEqual(Path(_native.__file__).resolve(), root / "_native.pyd")
        self.assertEqual(abc_crypto.ABI_VERSION, 0x00010000)
        self.assertEqual(abc_crypto.IMPLEMENTATION_ID, "sha256-abc-rust-portable")

    def test_byte_conversion(self):
        inputs = (
            b"",
            b"abc\x00\x80\xff",
            bytearray(range(256)),
            memoryview(b"0a1b2c")[1::2],
            array("B", [255, 0, 8]),
        )
        for value in inputs:
            with self.subTest(value=value):
                self.assertEqual(abc_crypto.sha256(value), sha256(bytes(value)).digest())
        with self.assertRaises(TypeError):
            abc_crypto.sha256("abc")
        with self.assertRaises(TypeError):
            abc_crypto.sha256(array("H", [128]))

    def test_streaming_output_lifecycle(self):
        with abc_crypto.Sha256() as digest:
            for chunk in (b"", bytearray(b"a"), memoryview(b"bc")):
                digest.update(chunk)
            self.assertEqual(digest.finalize(), sha256(b"abc").digest())
            for operation in (digest.finalize, lambda: digest.update(b"more")):
                with self.assertRaisesRegex(ValueError, "finalized"):
                    operation()
            digest.reset()
            self.assertEqual(digest.finalize(), sha256(b"").digest())
        digest.close()
        for operation in (digest.reset, digest.finalize, lambda: digest.update(b"")):
            with self.assertRaisesRegex(ValueError, "closed"):
                operation()

    def test_context_ownership(self):
        digest = abc_crypto.Sha256()
        for operation in (copy, deepcopy):
            with self.assertRaises(TypeError):
                operation(digest)
        state = ref(digest)
        del digest
        gc.collect()
        self.assertIsNone(state())


if __name__ == "__main__":
    unittest.main(verbosity=2)
