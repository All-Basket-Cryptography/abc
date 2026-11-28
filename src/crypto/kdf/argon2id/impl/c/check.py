"""Qualify C/C++ Argon2id against RFC 9106 and the Node or Go interface."""

import argparse
import ctypes as C
import hashlib
from itertools import product
import json
import os
from pathlib import Path
import random
import subprocess
import sys
from tempfile import TemporaryDirectory

import openssl_support as provider


HERE = Path(__file__).resolve().parent
SYMBOLS = "EVP_KDF_fetch EVP_KDF_CTX_new EVP_KDF_free EVP_KDF_CTX_free EVP_KDF_derive OSSL_PARAM_construct_octet_string OSSL_PARAM_construct_uint32 OSSL_PARAM_construct_end CRYPTO_malloc CRYPTO_clear_free".split()
RFC = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
CANARY = b"\xa5" * 8
NODE = r"""
const {readFileSync} = require('node:fs');
const {argon2Sync} = require('node:crypto');
const cases = JSON.parse(readFileSync(0, 'utf8'));
const decode = s => Buffer.from(s, 'hex');
const keys = cases.map(([memory, passes, parallelism, tagLength, msg, salt, sk, ad]) => {
  const input = {memory, passes, parallelism, tagLength, message: decode(msg), nonce: decode(salt)};
  if (sk !== '') input.secret = decode(sk);
  if (ad !== '') input.associatedData = decode(ad);
  return argon2Sync('argon2id', input).toString('hex');
});
console.log(JSON.stringify({node: process.version, openssl: process.versions.openssl, keys}));
"""


class Params(C.Structure):
    _fields_ = [(name, C.c_uint32) for name in ("memory", "passes", "lanes")]


class Bytes(C.Structure):
    _fields_ = [("data", C.c_char_p), ("size", C.c_size_t)]


def require(value, detail):
    if not value:
        raise ValueError(detail)


def fixture():
    rng = random.Random(9106)

    def params(lanes, segment, tag, index):
        lengths = (index % 6, 8 + index % 25, index % 13, index % 131)
        inputs = [rng.randbytes(length).hex() for length in lengths]
        return [4 * lanes * segment + index % (4 * lanes), 1 + index % 4, lanes, tag, *inputs]

    sizes = list(product((1, 2, 3, 4), (2, 3, 4, 7, 11), (4, 16, 32, 64, 65)))
    sizes.extend((1 + i % 3, 127 + i // 3, tag) for i, tag in enumerate((33, 63, 64, 65, 96, 97, 128, 129, 257)))
    return [[32, 3, 4, 32, "01" * 32, "02" * 16, "03" * 8, "04" * 12],
            *(params(lanes, segment, tag, index) for index, (lanes, segment, tag) in enumerate(sizes))]


def exercise(binary, with_go):
    dependency, version = provider.load(binary.parent)
    dll = C.CDLL(str(binary))
    derive = dll.abc_argon2id_c_derive
    derive.argtypes = [Params, Bytes, Bytes, Bytes, Bytes, C.c_size_t, C.c_void_p, C.c_size_t]
    derive.restype = C.c_int
    cases = fixture()
    oracle = json.loads(provider.run(["node", "-e", NODE], input=json.dumps(cases)))
    require(oracle["keys"][0] == RFC, "Node comparison failed RFC 9106")
    if with_go:
        encoded = "\n".join(":".join(map(str, row)) for row in cases) + "\n"
        go = provider.run(["go", "run", "-C", str(HERE.parent / "go"), "./internal/differential"],
                          env={**os.environ, "GOPROXY": "off", "CGO_ENABLED": "0"}, input=encoded)
        require(go.splitlines() == oracle["keys"], "independent Go comparison")
    for row, wanted in zip(cases, oracle["keys"], strict=True):
        memory, passes, lanes, width, *parts = row
        data = [bytes.fromhex(part) for part in parts]
        inputs = [Bytes(item or None, len(item)) for item in data]
        output = C.create_string_buffer(CANARY + bytes(width) + CANARY, width + 16)
        require(derive(Params(memory, passes, lanes), *inputs, memory * 1024, C.byref(output, 8), width) == 0,
                f"Argon2id provider rejected admissible input {row[:4]}")
        require(output.raw == CANARY + bytes.fromhex(wanted) + CANARY, f"Argon2id result differs at {row[:4]}")

    empty, salt = Bytes(None, 0), Bytes(b"12345678", 8)
    output = C.create_string_buffer(CANARY, len(CANARY))
    for invalid in (Params(32, 0, 4), Params(31, 3, 4), Params(32, 3, 0), Params(1 << 27, 3, 1 << 24)):
        require(derive(invalid, empty, salt, empty, empty, 32768, output, 8) == 1, "parameter preflight")
    valid = Params(32, 3, 4)
    require(derive(valid, empty, salt, empty, empty, 32767, output, 8) == 3, "requested memory budget")
    require(derive(valid, empty, Bytes(b"tooshort"[:7], 7), empty, empty, 32768, output, 8) == 2, "short salt")
    require(derive(valid, empty, salt, empty, empty, 32768, output, 3) == 2, "short tag")
    require(derive(valid, Bytes(b"X", 1 << 32), salt, empty, empty, 32768, output, 8) == 2, "length encoding")
    require(output.raw == CANARY, "preflight changed output")
    print(json.dumps({"provider": version, "node": oracle["node"], "node_openssl": oracle["openssl"],
                      "known_answers": 1, "comparison_cases": len(cases) - 1, "native_go_oracle": with_go}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("c", "cpp"), default="c")
    parser.add_argument("--go-oracle", action="store_true")
    parser.add_argument("--exercise", type=Path, help=argparse.SUPPRESS)
    provider.options(parser)
    args = parser.parse_args()
    if args.exercise:
        exercise(args.exercise, args.go_oracle)
        return
    cpp = args.language == "cpp"
    leaf = HERE.parent / args.language
    source = leaf / ("argon2id.cpp" if cpp else "abc_argon2id_c.c")
    sources = [source, leaf / "tests.cpp"] if cpp else [source]
    with TemporaryDirectory(prefix="abc-argon2id-openssl-") as scratch:
        binary, qualification = provider.build(Path(scratch), args, sources, ["-DABC_ARGON2ID_C_BUILD_DLL"], SYMBOLS, cpp)
        child = [sys.executable, "-B", str(__file__), "--exercise", str(binary)]
        if args.go_oracle:
            child.append("--go-oracle")
        report = json.loads(provider.run(child))
        require(report["provider"].split()[1] == qualification["headers"], "header and provider versions differ")
        print(json.dumps({"status": "passed", "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                          **qualification, **report}, indent=2))


if __name__ == "__main__":
    main()
