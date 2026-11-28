"""Conformance fixture runner shared by the six Python SDKs."""

import hashlib
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[4]
CRYPTO = ROOT / 'src' / 'crypto'
HEX = bytes.fromhex


def fixture(path):
    return json.loads((CRYPTO / path).read_text(encoding='utf-8'))


def javascript(path, expression, *data):
    source = f"""
import * as api from './src/crypto/{path}';
const args = process.argv.slice(1).map(value => Buffer.from(value, 'hex'));
console.log(Buffer.from({expression}).toString('hex'));
"""
    result = subprocess.run(['node', '--input-type=module', '-e', source, *(v.hex() for v in data)],
                            cwd=ROOT, check=True, capture_output=True, text=True, timeout=30)
    return HEX(result.stdout.strip())


def test_class(profile, api):
    class TestProfile(unittest.TestCase):
        def test_conformance(self):
            getattr(self, profile)()

        def argon2id(self):
            options = dict(memory_kib=32, passes=3, lanes=4, length=32, memory_limit=32800,
                           secret=b'\x03' * 8, associated_data=b'\x04' * 12)
            password, salt = b'\x01' * 32, b'\x02' * 16
            self.assertEqual(api.derive(password, salt, **options),
                             HEX('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659'))
            self.assertEqual(api.workspace_bytes(49, 3), 48 * 1024)
            with self.assertRaises(ValueError):
                api.derive(password, salt, **(options | {'memory_limit': 32799}))
            with self.assertRaises(ValueError):
                api.derive(password, salt[:7], **options)
            uneven = options | {'memory_kib': 49, 'lanes': 3, 'memory_limit': 48 * 1024 + 32}
            self.assertEqual(len(api.derive(password, salt, **uneven)), 32)
            with self.assertRaises(ValueError):
                api.derive(password, salt, **(uneven | {'memory_limit': 48 * 1024 + 31}))

        def x25519(self):
            alice = HEX('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
            bob = HEX('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
            key = api.public_key(alice)
            self.assertEqual(key.hex(), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
            self.assertEqual(api.shared_secret(alice, bob).hex(),
                             '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')
            self.assertEqual(api.shared_secret(alice, b'\xf6' + b'\xff' * 31), key)
            self.assertIsNone(api.shared_secret(alice, bytes(32)))
            with self.assertRaises(ValueError):
                api.shared_secret(alice, bytes(31))

        def ed25519(self):
            seed = HEX('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
            key = api.public_key(seed)
            sig = api.sign(seed, b'')
            self.assertEqual(key.hex(), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
            self.assertEqual(sig.hex(), 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
                                        '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
            self.assertTrue(api.verify(key, b'', sig))
            self.assertFalse(api.verify(key, b'wrong', sig))
            for bad in (bytes(32), b'\x01' + bytes(31), bytes([255]) * 32):
                self.assertFalse(api.verify(bad, b'', sig))
                self.assertFalse(api.verify(key, b'', bad + sig[32:]))
            self.assertFalse(api.verify(key, b'', sig[:32] + bytes([255]) * 32))

        def ecdsa_p256(self):
            private = HEX('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721')
            key = api.public_key(private)
            self.assertEqual(key.hex(), '0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6'
                                        '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299')
            for message, expected in [
                (b'sample', 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716'
                            'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8'),
                (b'test', 'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367'
                          '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083'),
            ]:
                sig = api.sign(private, message)
                self.assertEqual(sig.hex(), expected)
                self.assertTrue(api.verify(b'\x03' + key[1:33], message, sig))
                self.assertFalse(api.verify(key, message + b'!', sig))
            with self.assertRaises(ValueError):
                api.sign(bytes(32), b'')

        def ml_kem_768(self):
            path = 'agreement/ml-kem-768/impl/javascript/ml_kem_768.mjs'
            for row in fixture('agreement/ml-kem-768/spec/acvp.json')['cases']:
                if 'd' not in row or 'z' not in row:
                    continue
                seed = HEX(row['d'] + row['z'])
                key = api.public_key(seed)
                self.assertEqual(key, HEX(row['ek']))
                ct, secret = api.encapsulate(key)
                self.assertEqual(javascript(path, 'api.decapsulate(...args)', seed, ct), secret)
                packed = javascript(path, '(() => { const r = api.encapsulate(args[0]); '
                                    'return Buffer.concat([r.ciphertext, r.sharedSecret]); })()', key)
                self.assertEqual(api.decapsulate(seed, packed[:1088]), packed[1088:])
                invalid = bytes([ct[0] ^ 1]) + ct[1:]
                self.assertEqual(api.decapsulate(seed, invalid), hashlib.shake_256(seed[32:] + invalid).digest(32))
                with self.assertRaises(ValueError):
                    api.decapsulate(seed, ct[:-1])
            with self.assertRaises(ValueError):
                api.encapsulate(bytes([255]) * 1184)

        def ml_dsa_65(self):
            path = 'signature/ml-dsa-65/impl/javascript/ml_dsa_65.mjs'
            cases = fixture('signature/ml-dsa-65/spec/acvp-fips204-sample.json')
            seed = HEX(cases['keyGen']['seed'])
            key = api.public_key(seed)
            self.assertEqual(hashlib.sha256(key).hexdigest(), cases['keyGen']['public_key_sha256'])
            for category in ('sigGen', 'sigVer'):
                for row in cases[category]['cases']:
                    self.assertEqual(api.verify(HEX(row['pk']), HEX(row['message']), HEX(row['signature']),
                                                HEX(row['context'])), row.get('testPassed', True))
            for context in (b'', b'\x00\xff', bytes(range(255))):
                message = b'ABC deterministic ML-DSA-65 test'
                sig = api.sign(seed, message, context)
                self.assertEqual(sig, javascript(path, 'api.sign(...args)', seed, message, context))
                self.assertTrue(api.verify(key, message, sig, context))
                self.assertFalse(api.verify(key, message, sig, context + b'\x01'))
            with self.assertRaises(ValueError):
                api.sign(seed, b'', bytes(256))

    return TestProfile
