"""Build native C11 or C++17 ChaCha20/Poly1305 and compare independent results."""

import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
BRIDGE = HERE.parent / "cpp/check_bridge.cpp"
METHODS = {"chacha20": "cipher/chacha20", "poly1305": "mac/poly1305",
           "aead": "aead/chacha20-poly1305"}
NAMES = {"chacha20": "chacha20", "poly1305": "poly1305", "aead": "chacha20_poly1305"}
DEFINITIONS = {"chacha20": "ABC_TEST_CHACHA", "poly1305": "ABC_TEST_POLY", "aead": "ABC_TEST_AEAD"}
CANARY = bytes([0xa9] * 32)
PLAINTEXT = bytes.fromhex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e")


def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=90, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}\n"
                           + (result.stdout + result.stderr).decode("utf-8", errors="replace"))
    return result.stdout


def build(language, selected, directory, ubsan):
    compiled = list(METHODS) if "aead" in selected else selected
    include_dirs = [CRYPTO / METHODS[method] / "impl" / language for method in compiled]
    sources = []
    evidence = [BRIDGE]
    for method, leaf in zip(compiled, include_dirs):
        name = NAMES[method]
        if language == "c":
            source = leaf / f"abc_{name}_c.c"
            header = leaf / f"abc_{name}_c.h"
        else:
            source = leaf / f"{name}.cpp"
            header = leaf / f"{name}.hpp"
        sources.append(source)
        evidence.extend([source, header])
    flags = ["-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-fvisibility=hidden"]
    if sys.platform == "win32":
        flags.append("-fms-runtime-lib=static" if ubsan else "-fms-runtime-lib=dll")
    else:
        flags.append("-fPIC")
    if ubsan:
        flags += ["-fsanitize=undefined", "-fno-sanitize-recover=all"]
    includes = [argument for path in include_dirs for argument in ("-I", str(path))]
    objects = []
    for number, source in enumerate(sources):
        target = directory / f"core-{number}.o"
        mode = ["-std=c11"] if language == "c" else ["--driver-mode=g++", "-std=c++17"]
        run(["clang", *mode, *flags, *includes, "-c", str(source), "-o", str(target)])
        objects.append(str(target))
    suffix = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
    mode = "-dynamiclib" if sys.platform == "darwin" else "-shared"
    library = directory / f"checks{suffix}"
    features = ["-D" + DEFINITIONS[method] for method in selected]
    if language == "c":
        features.append("-DABC_TEST_C")
    run(["clang", "--driver-mode=g++", "-std=c++17", *flags, *includes, *features,
         mode, str(BRIDGE), *objects, "-o", str(library)])
    hashes = {item.relative_to(CRYPTO).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
              for item in evidence}
    return C.CDLL(str(library)), hashes


def bind(library, name, arguments, result=C.c_int):
    function = getattr(library, f"test_{name}")
    function.argtypes = arguments
    function.restype = result
    return function


def output(length):
    initial = bytes([0x83]) * length + CANARY
    return C.create_string_buffer(initial, len(initial))


NODE_ORACLE = r"""
const {createCipheriv, createDecipheriv} = require('node:crypto');
const fs = require('node:fs');
const decode = s => Buffer.from(s, 'hex');
const output = JSON.parse(fs.readFileSync(0, 'utf8')).map(test => {
  const key = decode(test.key), nonce = decode(test.nonce), message = decode(test.message);
  if (test.mode === 'chacha20') {
    const iv = Buffer.alloc(16);
    iv.writeUInt32LE(test.counter);
    nonce.copy(iv, 4);
    const cipher = createCipheriv('chacha20', key, iv);
    return {ciphertext: Buffer.concat([cipher.update(message), cipher.final()]).toString('hex')};
  }
  const aad = decode(test.aad);
  const seal = createCipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  seal.setAAD(aad);
  const ciphertext = Buffer.concat([seal.update(message), seal.final()]);
  const open = createDecipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  open.setAAD(aad);
  open.setAuthTag(decode(test.tag));
  if (!Buffer.concat([open.update(decode(test.ciphertext)), open.final()]).equals(message))
    throw Error('native ciphertext did not open');
  return {ciphertext: ciphertext.toString('hex'), tag: seal.getAuthTag().toString('hex')};
});
process.stdout.write(JSON.stringify({version: process.versions.openssl, output}));
"""


def node_cases(cases):
    reply = json.loads(run(["node", "-e", NODE_ORACLE], input=json.dumps(cases).encode("utf-8")))
    if len(cases) != len(reply["output"]):
        raise ValueError("OpenSSL response length differs")
    return reply


def check_chacha(library):
    ptr, size, counter = C.c_void_p, C.c_size_t, C.c_uint32
    stream = bind(library, "stream", [ptr, ptr, counter, ptr, size, ptr, size])
    block = bind(library, "block", [ptr, ptr, counter, ptr, size])
    fits = bind(library, "fits", [C.c_uint64, counter])

    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    wire = output(64)
    assert block(key, nonce, 1, wire, len(wire)) == 0
    assert wire.raw[:64].hex() == (
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
    assert wire.raw[64:] == CANARY
    nonce = bytes.fromhex("000000000000004a00000000")
    length = len(PLAINTEXT)
    wire = output(length)
    assert stream(key, nonce, 1, PLAINTEXT, length, wire, len(wire)) == 0
    assert wire.raw[:length].hex() == (
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d")
    for start in (0, 1, (1 << 32) - 2, (1 << 32) - 1):
        boundary = ((1 << 32) - start) * 64
        assert fits(0, start) and fits(boundary, start) and not fits(boundary + 1, start)

    initial = wire.raw
    assert stream(key, nonce, (1 << 32) - 1, PLAINTEXT, 65, wire, len(wire)) == 3
    assert stream(key, nonce, 1, PLAINTEXT, length, wire, length - 1) == 2
    assert stream(key, nonce, 1, None, 1, wire, len(wire)) == 1
    assert wire.raw == initial
    assert stream(key, nonce, (1 << 32) - 1, None, 0, None, 0) == 0
    for source, destination in ((1, 7), (7, 1), (7, 7)):
        aliased = output(length + 16)
        C.memmove(C.byref(aliased, source), PLAINTEXT, length)
        tail = aliased.raw[destination + length:]
        assert stream(key, nonce, 1, C.byref(aliased, source), length,
                      C.byref(aliased, destination), length) == 0
        assert aliased.raw[destination:destination + length] == initial[:length]
        assert aliased.raw[destination + length:] == tail

    rng = random.Random(843920)
    lengths = [0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257]
    oracle = []
    expected = []
    for i in range(144):
        width = lengths[i] if i < len(lengths) else 64 if i == len(lengths) else rng.randrange(514)
        ctr = (1 << 32) - 1 if i == len(lengths) else rng.randrange(512)
        key, nonce, message = rng.randbytes(32), rng.randbytes(12), rng.randbytes(width)
        wire = output(width)
        assert stream(key, nonce, ctr, message, width, wire, len(wire)) == 0
        assert wire.raw[width:] == CANARY
        oracle.append(dict(mode="chacha20", key=key.hex(), nonce=nonce.hex(),
                           counter=ctr, message=message.hex()))
        expected.append(wire.raw[:width].hex())
    ref = node_cases(oracle)
    assert [item["ciphertext"] for item in ref["output"]] == expected
    return {"rfc_known": 2, "openssl_cases": len(expected), "openssl_version": ref["version"]}


def poly_oracle(key, message):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    state = 0
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        state = (state + int.from_bytes(block + b"\x01", "little")) * r % ((1 << 130) - 5)
    return ((state + s) % (1 << 128)).to_bytes(16, "little")


def poly_cases():
    def block(first, rest=0):
        return bytes([first]) + bytes([rest]) * 15

    zero, one, two, ones = block(0), block(1), block(2), block(255, 255)
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


def check_poly(library, openssl):
    ptr, size = C.c_void_p, C.c_size_t
    auth = bind(library, "poly", [ptr, ptr, size, ptr, size])
    stream = bind(library, "poly_split", [ptr, ptr, size, size, ptr])
    known = poly_cases()
    for key, message, expected in known:
        tag = output(16)
        assert auth(key, message, len(message), tag, len(tag)) == 0
        assert tag.raw == expected + CANARY
        for split in range(len(message) + 1):
            assert stream(key, message, len(message), split, tag) == 0
            assert tag.raw == expected + CANARY
    rng = random.Random(84391305)
    external = 0
    for index in range(512):
        width = index if index < 96 else rng.randrange(1025)
        key, message = rng.randbytes(32), rng.randbytes(width)
        tag = output(16)
        expected = poly_oracle(key, message)
        assert auth(key, message, width, tag, len(tag)) == 0
        assert tag.raw == expected + CANARY
        assert stream(key, message, width, rng.randrange(width + 1), tag) == 0
        assert tag.raw == expected + CANARY
        if index < 32 and openssl is not None:
            reference = run([openssl, "mac", "-macopt", "hexkey:" + key.hex(), "POLY1305"],
                            input=message)
            assert bytes.fromhex(reference.decode().strip()) == expected
            external += 1
    tag = output(16)
    before = tag.raw
    assert auth(None, None, 0, tag, len(tag)) == 1
    assert auth(bytes(32), None, 1, tag, len(tag)) == 1
    assert auth(bytes(32), None, 0, tag, 15) == 2
    assert tag.raw == before
    assert auth(bytes(32), None, 0, tag, len(tag)) == 0 and tag.raw == bytes(16) + CANARY
    key, message, want = known[0]
    alias = C.create_string_buffer(message, len(message))
    assert auth(key, alias, len(message), C.byref(alias, 1), 16) == 0
    assert alias.raw[1:17] == want
    report = {"rfc_known": len(known), "integer_comparisons": 512, "openssl_cases": external}
    if external:
        report["openssl_version"] = run([openssl, "version"]).decode().strip()
    return report


def check_aead(library):
    ptr, size = C.c_void_p, C.c_size_t
    signature = [ptr, ptr, ptr, size, ptr, size, ptr, size, ptr, size]
    seal = bind(library, "seal", signature)
    open_msg = bind(library, "open", signature)
    assert bind(library, "overlapping_tag", [])() == 1

    def encrypted(key, nonce, aad, message):
        ciphertext, tag = output(len(message)), output(16)
        assert seal(key, nonce, aad, len(aad), message, len(message), ciphertext,
                    len(ciphertext), tag, len(tag)) == 0
        width = len(message)
        assert ciphertext.raw[width:] == CANARY and tag.raw[16:] == CANARY
        return ciphertext.raw[:width], tag.raw[:16]

    key = bytes(range(0x80, 0xa0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    ciphertext, tag = encrypted(key, nonce, aad, PLAINTEXT)
    assert ciphertext.hex() == (
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116")
    assert tag.hex() == "1ae10b594f09e26a7e902ecbd0600691"
    width = len(PLAINTEXT)
    alias = output(width + 32)
    C.memmove(alias, PLAINTEXT, width)
    C.memmove(C.byref(alias, width + 8), aad, len(aad))
    alias_tag = output(16)
    assert seal(key, nonce, C.byref(alias, width + 8), len(aad), alias, width,
                C.byref(alias, 12), width, alias_tag, len(alias_tag)) == 0
    assert alias.raw[12:12 + width] == ciphertext and alias_tag.raw[:16] == tag
    C.memmove(C.byref(alias, 12), ciphertext, width)
    C.memmove(alias, aad, len(aad))
    assert open_msg(key, nonce, alias, len(aad), C.byref(alias, 12), width,
                    C.byref(alias, 3), width, tag, len(tag)) == 0
    assert alias.raw[3:3 + width] == PLAINTEXT

    rejected = output(width)
    preserved = rejected.raw
    for index in range(16):
        wrong = bytearray(tag)
        wrong[index] ^= 1
        assert open_msg(key, nonce, aad, len(aad), ciphertext, width, rejected, len(rejected),
                        bytes(wrong), 16) == 4
        assert rejected.raw == preserved
        in_place = C.create_string_buffer(ciphertext, width)
        assert open_msg(key, nonce, aad, len(aad), in_place, width, in_place, width,
                        bytes(wrong), 16) == 4
        assert in_place.raw == ciphertext
    assert open_msg(key, nonce, b"wrong", 5, ciphertext, width, rejected, len(rejected), tag, 16) == 4
    assert open_msg(key, nonce, aad, len(aad), ciphertext, width, rejected, len(rejected), tag, 15) == 1
    wrong_cipher = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    assert open_msg(key, nonce, aad, len(aad), wrong_cipher, width, rejected, len(rejected), tag, 16) == 4
    assert rejected.raw == preserved
    tag_canary = output(16)
    saved = tag_canary.raw
    assert seal(key, nonce, aad, len(aad), PLAINTEXT, width, rejected, width - 1,
                tag_canary, len(tag_canary)) == 2
    assert seal(key, nonce, aad, len(aad), PLAINTEXT, width, rejected, len(rejected),
                tag_canary, 15) == 2
    assert tag_canary.raw == saved and rejected.raw == preserved

    rng = random.Random(8439)
    boundaries = [0, 1, 15, 16, 17, 63, 64, 65]
    provider_input, fixtures = [], []
    for number in range(174):
        width, aad_width = rng.randrange(1025), rng.randrange(144)
        if number < len(boundaries) ** 2:
            width, aad_width = boundaries[number // len(boundaries)], boundaries[number % len(boundaries)]
        key, nonce = rng.randbytes(32), rng.randbytes(12)
        aad, message = rng.randbytes(aad_width), rng.randbytes(width)
        cipher, tag = encrypted(key, nonce, aad, message)
        provider_input.append(dict(mode="aead", key=key.hex(), nonce=nonce.hex(), aad=aad.hex(),
                                   message=message.hex(), ciphertext=cipher.hex(), tag=tag.hex()))
        fixtures.append((key, nonce, aad, message))
    ref = node_cases(provider_input)
    for expected, (key, nonce, aad, message), given in zip(ref["output"], fixtures, provider_input):
        assert expected["ciphertext"] == given["ciphertext"] and expected["tag"] == given["tag"]
        ciphertext, tag = bytes.fromhex(expected["ciphertext"]), bytes.fromhex(expected["tag"])
        clear = output(len(message))
        assert open_msg(key, nonce, aad, len(aad), ciphertext, len(message), clear, len(clear),
                        tag, len(tag)) == 0
        assert clear.raw == message + CANARY
    return {"rfc_known": 1, "bidirectional_openssl_cases": len(fixtures), "openssl_version": ref["version"]}


def main():
    if not __debug__:
        raise RuntimeError("The conformance program requires Python assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=["c", "cpp"], default="c")
    parser.add_argument("--profile", choices=[*METHODS, "all"], default="all")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--ubsan", action="store_true")
    parser.add_argument("--openssl")
    arguments = parser.parse_args()
    if arguments.benchmark and arguments.ubsan:
        parser.error("benchmark the uninstrumented build")
    selected = list(METHODS) if arguments.profile == "all" else [arguments.profile]
    with TemporaryDirectory(prefix="abc-rfc8439-native-") as temporary:
        library, hashes = build(arguments.language, selected, Path(temporary), arguments.ubsan)
        checks = {"chacha20": check_chacha, "aead": check_aead,
                  "poly1305": lambda loaded: check_poly(loaded, arguments.openssl)}
        report = {"status": "passed", "language": arguments.language, "target": platform.machine(),
                  "compiler": run(["clang", "--version"]).decode().splitlines()[:2],
                  "ubsan": arguments.ubsan, "sources_sha256": hashes,
                  "results": {method: checks[method](library) for method in selected}}
        if arguments.benchmark:
            time = bind(library, "time", [C.c_int, C.c_size_t, C.c_size_t], C.c_uint64)
            measurements = {}
            for method in selected:
                number = list(METHODS).index(method) + 1
                for width in (64, 4096):
                    samples = [time(number, width, 1024) for _ in range(5)]
                    if min(samples) == 0:
                        raise RuntimeError("native benchmark failed")
                    measurements[f"{method}_{width}"] = statistics.median(samples)
            report["benchmark_median_ns_per_call"] = measurements
        print(json.dumps(report))
        if sys.platform == "win32":
            import _ctypes
            _ctypes.FreeLibrary(library._handle)


if __name__ == "__main__":
    main()
