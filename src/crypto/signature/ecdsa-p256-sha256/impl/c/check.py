"""Check deterministic ECDSA P-256/SHA-256 against RFC 6979 and OpenSSL."""

import argparse
import ctypes as C
import hashlib
import hmac
import json
from pathlib import Path
import random
import runpy
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
provider = runpy.run_path(str(HERE.parents[3] / "kdf/argon2id/impl/c/openssl_support.py"))
SYMBOLS = """BN_secure_new BN_bin2bn BN_clear_free BN_set_flags BN_CTX_secure_new BN_CTX_free BN_dup BN_free
BN_is_zero BN_nnmod BN_bn2binpad BN_sub_word BN_mod_exp_mont_consttime EC_GROUP_new_by_curve_name EC_GROUP_get0_order
EC_GROUP_free EC_POINT_new EC_POINT_free EC_POINT_mul EC_POINT_get_affine_coordinates EC_POINT_point2oct
EC_POINT_oct2point EC_POINT_is_on_curve EC_POINT_is_at_infinity EC_KEY_new_by_curve_name EC_KEY_get0_group
EC_KEY_set_private_key EC_KEY_set_public_key EC_KEY_free ECDSA_do_sign_ex ECDSA_do_verify ECDSA_SIG_new
ECDSA_SIG_free ECDSA_SIG_get0 ECDSA_SIG_set0 ERR_peek_last_error ERR_set_mark ERR_pop_to_mark ERR_clear_error
EVP_Q_digest EVP_Q_mac OPENSSL_cleanse""".split()
ORDER = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
SCALAR = bytes.fromhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
PUBLIC = bytes.fromhex("0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")
RFC = (
    (b"sample", "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"),
    (b"test", "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"),
)
NODE = r"""
const c = require('node:crypto');
const {readFileSync} = require('node:fs');
const rows = JSON.parse(readFileSync(0, 'utf8'));
const bytes = text => Buffer.from(text, 'hex');
const output = rows.map(([scalar, point, message, candidate]) => {
  const curve = c.createECDH('prime256v1');
  curve.setPrivateKey(bytes(scalar));
  const publicPoint = curve.getPublicKey();
  if (publicPoint.toString('hex') !== point) throw new Error('SEC 1 public key mismatch');
  const jwk = {kty:'EC', crv:'P-256', d:bytes(scalar).toString('base64url'),
    x:publicPoint.subarray(1,33).toString('base64url'), y:publicPoint.subarray(33).toString('base64url')};
  const key = c.createPrivateKey({format:'jwk',key:jwk});
  const verify = {key:c.createPublicKey(key), dsaEncoding:'ieee-p1363'};
  if (!c.verify('sha256', bytes(message), verify, bytes(candidate))) throw new Error('verification mismatch');
  return c.sign('sha256', bytes(message), {key, dsaEncoding:'ieee-p1363'}).toString('hex');
});
console.log(JSON.stringify({node: process.version, openssl: process.versions.openssl, output}));
"""


def require(value, detail):
    if not value:
        raise ValueError(detail)


def octets(number):
    return number.to_bytes(32, "big")


def nonce_reference(scalar, digest):
    key, v = bytes(32), bytes([1]) * 32
    seed = scalar + octets(int.from_bytes(digest, "big") % ORDER)
    for marker in (b"\x00", b"\x01"):
        key = hmac.digest(key, v + marker + seed, "sha256")
        v = hmac.digest(key, v, "sha256")
    first = hmac.digest(key, v, "sha256")
    key = hmac.digest(key, first + b"\x00", "sha256")
    v = hmac.digest(key, first, "sha256")
    return first + hmac.digest(key, v, "sha256")


def exercise(binary, language, hooks):
    dependency, version = provider["load"](binary.parent)
    api = C.CDLL(str(binary))
    prefix = f"abc_ecdsa_p256_sha256_{language}_"
    pointer, size = C.c_void_p, C.c_size_t

    def bind(name, *arguments):
        function = getattr(api, name)
        function.argtypes, function.restype = arguments, C.c_int
        return function

    public = bind(prefix + "public_key", pointer, pointer)
    sign = bind(prefix + "sign", pointer, pointer, size, pointer)
    verify = bind(prefix + "verify", pointer, size, pointer, size, pointer)
    p = C.create_string_buffer(65)
    s = C.create_string_buffer(b"\xa5" * 66, 66)
    out = C.byref(s, 1)
    require(public(SCALAR, p) == 0 and p.raw == PUBLIC, "RFC public key")
    compressed = bytes([2 | (PUBLIC[-1] & 1)]) + PUBLIC[1:33]
    for message, want in RFC:
        expected = bytes.fromhex(want)
        for _ in range(2):
            require(sign(SCALAR, message, len(message), out) == 0 and s.raw == b"\xa5" + expected + b"\xa5",
                    "RFC deterministic signature")
        low_or_high = expected[:32] + octets(ORDER - int.from_bytes(expected[32:], "big"))
        for point in (PUBLIC, compressed):
            require(verify(point, len(point), message, len(message), expected) == 0, "SEC 1 verification")
            require(verify(point, len(point), message, len(message), low_or_high) == 0, "alternate S verification")
    before = s.raw
    message, raw = RFC[0][0], bytes.fromhex(RFC[0][1])
    for scalar in (0, ORDER, (1 << 256) - 1):
        require(public(octets(scalar), p) == 1 and p.raw == PUBLIC, "private scalar bounds")
        require(sign(octets(scalar), message, len(message), out) == 1 and s.raw == before, "invalid private scalar preserves output")
    for point in (b"\x00", b"\x06" + PUBLIC[1:], b"\x04" + bytes(64), PUBLIC[:64], compressed + bytes(1)):
        require(verify(point, len(point), message, len(message), raw) == 2, "invalid public point")
    for bad in (bytes(32) + raw[32:], raw[:32] + octets(ORDER)):
        require(verify(PUBLIC, 65, message, len(message), bad) == 2, "invalid signature scalar")
    require(verify(PUBLIC, 65, b"tampered", 8, raw) == 2, "altered message")

    if hooks:
        candidate = bind("abc_p256_c_sign_candidate", pointer, pointer, pointer, pointer)
        trace = bind("abc_p256_c_nonce_transcript", pointer, pointer, pointer)
        generator_x = int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
        zero_s_digest = octets(ORDER - generator_x)
        for k, digest in ((0, bytes(32)), (ORDER, bytes(32)), (1, zero_s_digest)):
            require(candidate(octets(1), digest, octets(k), out) == 4 and s.raw == before, "candidate rejection preserves output")
        for digest in (hashlib.sha256(b"sample").digest(), octets(ORDER), octets((1 << 256) - 1)):
            require(trace(SCALAR, digest, out) == 0 and s.raw == b"\xa5" + nonce_reference(SCALAR, digest) + b"\xa5",
                    "RFC6979 rejection continuation and bits2octets")
    else:
        require(not hasattr(api, "abc_p256_c_sign_candidate") and not hasattr(api, "abc_p256_c_nonce_transcript"), "test hooks exported")

    rng = random.Random(6979)
    rows = []
    for length in (0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 128, 1024):
        for _ in range(4):
            d = octets(rng.randrange(1, ORDER))
            data = rng.randbytes(length)
            require(public(d, p) == 0 and sign(d, data or None, length, out) == 0, "interoperability inputs")
            rows.append((d, p.raw, data, s.raw[1:-1]))
    oracle = json.loads(provider["run"](["node", "-e", NODE], input=json.dumps([[item.hex() for item in row] for row in rows])))
    for (_, point, data, _), expected in zip(rows, oracle["output"], strict=True):
        require(verify(point, 65, data or None, len(data), bytes.fromhex(expected)) == 0, "accept external signature")
    print(json.dumps({"provider": version, "rfc_signatures": 2, "rfc_public_keys": 1, "openssl_bidirectional": len(rows),
                      "node": oracle["node"], "node_openssl": oracle["openssl"], "candidate_rejections": 3 if hooks else 0,
                      "nonce_retry_transcripts": 3 if hooks else 0}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("c", "cpp"), default="c")
    parser.add_argument("--exercise", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--hooks", action="store_true", help=argparse.SUPPRESS)
    provider["options"](parser)
    args = parser.parse_args()
    if args.exercise:
        exercise(args.exercise, args.language, args.hooks)
        return
    cpp = args.language == "cpp"
    wrapper = HERE / "abc_ecdsa_p256_sha256_c.c"
    nonce = HERE / "ecdsa_p256_nonce.c"
    entry = HERE.parent / "cpp/ecdsa_p256_sha256.cpp" if cpp else wrapper
    report = {}
    for hooks in (False, True):
        with TemporaryDirectory(prefix="abc-ecdsa-openssl-") as scratch:
            work = Path(scratch)
            flags = ["-DABC_ECDSA_P256_TEST_SUPPORT"] if hooks else []
            sources = [wrapper, nonce]
            if cpp:
                c_objects = []
                instrumentation = ["-fsanitize=undefined", "-fsanitize-trap=undefined"] if args.ubsan else []
                for source in sources:
                    dest = work / (source.stem + ".obj")
                    provider["run"](["clang", "--driver-mode=gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                                     "-I", str(args.openssl_include), *flags, *instrumentation, "-c", str(source), "-o", str(dest)])
                    c_objects.append(dest)
                sources = [entry, entry.with_name("tests.cpp"), *c_objects]
            else:
                flags.append("-DABC_ECDSA_P256_C_BUILD_DLL")
            binary, qualification = provider["build"](work, args, sources, flags, SYMBOLS, cpp)
            command = [sys.executable, "-B", str(__file__), "--language", args.language, "--exercise", str(binary)]
            if hooks:
                command.append("--hooks")
            result = json.loads(provider["run"](command))
            require(result["provider"].split()[1] == qualification["headers"], "header and provider versions differ")
            report.update(qualification)
            report.update(result)
    print(json.dumps({"status": "passed", "sources_sha256": {item.name: hashlib.sha256(item.read_bytes()).hexdigest()
                                                             for item in (entry, nonce)}, **report}, indent=2))


if __name__ == "__main__":
    main()
