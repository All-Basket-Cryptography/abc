"""Qualify C/C++ pure Ed25519 with the strict RFC 8032 decoding policy."""

import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import runpy
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
provider = runpy.run_path(str(HERE.parents[3] / "kdf/argon2id/impl/c/openssl_support.py"))
SYMBOLS = "EVP_PKEY_new_raw_private_key_ex EVP_PKEY_new_raw_public_key_ex EVP_PKEY_get_raw_public_key EVP_PKEY_free EVP_MD_CTX_new EVP_MD_CTX_free EVP_DigestSignInit_ex EVP_DigestSign EVP_DigestVerifyInit_ex EVP_DigestVerify".split()
P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
RFC = (
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
)
NODE = r"""
const crypto = require('node:crypto');
const {readFileSync} = require('node:fs');
const rows = JSON.parse(readFileSync(0, 'utf8'));
const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
const output = rows.map(([seed, message]) => {
  const key = crypto.createPrivateKey({key: Buffer.concat([prefix, Buffer.from(seed, 'hex')]), format:'der', type:'pkcs8'});
  const pub = crypto.createPublicKey(key).export({format:'der', type:'spki'}).subarray(-32).toString('hex');
  return [seed, pub, message, crypto.sign(null, Buffer.from(message, 'hex'), key).toString('hex')];
});
console.log(JSON.stringify({node: process.version, openssl: process.versions.openssl, output}));
"""


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def torsion_encodings():
    d = -121665 * pow(121666, -1, P) % P
    ys = (0, 1, P - 1, *(int.from_bytes(bytes.fromhex(text), "little") for text in (
          "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
          "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")))

    def double(x, y):
        product = d * x * x * y * y % P
        return 2 * x * y * pow(1 + product, -1, P) % P, (y * y + x * x) * pow(1 - product, -1, P) % P

    points = []
    for y in ys:
        square = (y * y - 1) * pow(d * y * y + 1, -1, P) % P
        x = pow(square, (P + 3) // 8, P)
        if x * x % P != square:
            x = x * pow(2, (P - 1) // 4, P) % P
        require(x * x % P == square and double(*double(*double(x, y))) == (0, 1), "torsion fixture arithmetic")
        points.append(y.to_bytes(32, "little"))
        if x != 0:
            points.append((y | (1 << 255)).to_bytes(32, "little"))
    require(len(set(points)) == 8, "expected eight distinct torsion encodings")
    return points


def exercise(binary):
    dependency, version = provider["load"](binary.parent)
    dll = C.CDLL(str(binary))
    pub, sign, verify = (getattr(dll, "abc_ed25519_c_" + name) for name in ("public_key", "sign", "verify_strict"))
    pointer, size = C.c_void_p, C.c_size_t
    pub.argtypes = [pointer, pointer]
    sign.argtypes = verify.argtypes = [pointer, pointer, size, pointer]
    pub.restype = sign.restype = verify.restype = C.c_int
    rng = random.Random(8032)
    rows = [[rng.randbytes(32).hex(), rng.randbytes(length).hex()] for length in (0, 1, 2, 31, 32, 63, 64, 65, 257, 4097) for _ in range(4)]
    oracle = json.loads(provider["run"](["node", "-e", NODE], input=json.dumps(rows)))
    for row in (*RFC, *oracle["output"]):
        seed, key, message, signature = map(bytes.fromhex, row)
        output = C.create_string_buffer(b"\xa5" * 66, 66)
        dest = C.byref(output, 1)
        require(pub(seed, dest) == 0 and output.raw == b"\xa5" + key + b"\xa5" * 33, "raw public key")
        require(sign(seed, message or None, len(message), dest) == 0
                and output.raw == b"\xa5" + signature + b"\xa5", "deterministic pure signature")
        require(verify(key, message or None, len(message), signature) == 0, "valid signature")
        require(verify(key, message + b"x", len(message) + 1, signature) == 2, "wrong message")

    seed, key, message, signature = map(bytes.fromhex, RFC[2])
    rejected = [*torsion_encodings(), (1 | (1 << 255)).to_bytes(32, "little"), (P + 3).to_bytes(32, "little")]
    for point in rejected:
        require(verify(point, message, len(message), signature) == 2, "strict public key encoding")
        require(verify(key, message, len(message), point + signature[32:]) == 2, "strict commitment encoding")
    for scalar in (L, L + int.from_bytes(signature[32:], "little")):
        bad = signature[:32] + scalar.to_bytes(32, "little")
        require(verify(key, message, len(message), bad) == 2, "noncanonical scalar")
    output = C.create_string_buffer(seed + bytes(32), 64)
    require(sign(output, message, len(message), output) == 0 and output.raw == signature, "alias and key ownership")
    require(sign(seed, None, 1, output) == 1 and output.raw == signature, "invalid input preserves output")
    print(json.dumps({"provider": version, "rfc_known_answers": 3, "node_openssl_cases": len(oracle["output"]),
                      "node": oracle["node"], "node_openssl": oracle["openssl"], "strict_encoding_rejections": 22}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("c", "cpp"), default="c")
    parser.add_argument("--exercise", type=Path, help=argparse.SUPPRESS)
    provider["options"](parser)
    args = parser.parse_args()
    if args.exercise:
        exercise(args.exercise)
        return
    cpp = args.language == "cpp"
    leaf = HERE.parent / args.language
    source = leaf / ("ed25519.cpp" if cpp else "abc_ed25519_c.c")
    sources = [source, leaf / "tests.cpp"] if cpp else [source]
    with TemporaryDirectory(prefix="abc-ed25519-openssl-") as scratch:
        binary, qualification = provider["build"](Path(scratch), args, sources, ["-DABC_ED25519_C_BUILD_DLL"], SYMBOLS, cpp)
        report = json.loads(provider["run"]([sys.executable, "-B", str(__file__), "--exercise", str(binary)]))
        require(report["provider"].split()[1] == qualification["headers"], "header and provider versions differ")
        print(json.dumps({"status": "passed", "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                          **qualification, **report}, indent=2))


if __name__ == "__main__":
    main()
