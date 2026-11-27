"""Build native C PBKDF2-HMAC-SHA-256 and check it against RFC 7914 and OpenSSL."""

import argparse
import ctypes as C
from _hashlib import pbkdf2_hmac
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import runpy
import ssl
from subprocess import check_output
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
HMAC = HERE.parents[3] / "mac/hmac-sha256/impl/c"
OK, INVALID, LIMIT, ITERATIONS, OUTPUT_LENGTH = 0, 1, 2, 6, 7
MAX_PASSWORD = (1 << 61) - 1
MAX_SALT = MAX_PASSWORD - 64 - 4
MAX_OUTPUT = ((1 << 32) - 1) * 32
CANARY = b"\xa5" * 16


def validate(library, bind):
    if not __debug__:
        raise RuntimeError("The native conformance checks require Python assertions")
    native = C.CDLL(str(library))
    ptr, size = C.c_void_p, C.c_size_t
    derive = bind(native, "abc_pbkdf2_sha256_c_derive", [ptr, size, ptr, size, C.c_uint32, ptr, size])

    def expect(password, salt, iterations, expected):
        length = len(expected)
        initial = CANARY + b"\x00" * length + CANARY
        guarded = C.create_string_buffer(initial, len(initial))
        assert derive(password or None, len(password), salt or None, len(salt), iterations,
                      C.byref(guarded, len(CANARY)), length) == OK
        assert guarded.raw == CANARY + expected + CANARY

    rfc_vectors = (
        (
            b"passwd", b"salt", 1,
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        ),
        (
            b"Password", b"NaCl", 80000,
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
        ),
    )
    for password, salt, iterations, tag in rfc_vectors:
        expect(password, salt, iterations, bytes.fromhex(tag))

    passwords = (b"", b"pass\x00word", bytes(range(63)), bytes(range(64)),
                 bytes(range(65)), bytes(range(139)))
    salts = (b"", b"sal\x00t", bytes(range(60)), bytes(range(61)))
    sizes = ((1, 1), (2, 31), (3, 32), (4, 33), (7, 63), (8, 64), (9, 65), (32, 101))
    comparisons = 0
    for password, salt, (iterations, length) in product(passwords, salts, sizes):
        expect(password, salt, iterations, pbkdf2_hmac("sha256", password, salt, iterations, length))
        comparisons += 1
    for length in (8159, 8160, 8161, 8192):
        expect(b"counter", b"index", 2, pbkdf2_hmac("sha256", b"counter", b"index", 2, length))
        comparisons += 1

    output = C.create_string_buffer(CANARY, len(CANARY))
    assert derive(None, 1, None, 0, 1, output, 1) == INVALID
    assert derive(None, 0, None, 1, 1, output, 1) == INVALID
    assert derive(None, 0, None, 0, 1, None, 1) == INVALID
    assert derive(None, 0, None, 0, 0, output, 1) == ITERATIONS
    assert derive(None, 0, None, 0, (1 << 32) - 1, output, 0) == OUTPUT_LENGTH
    wide = C.sizeof(size) >= 8
    if wide:
        assert derive(None, 0, None, 0, 1, output, MAX_OUTPUT + 1) == OUTPUT_LENGTH
        assert derive(b"x", MAX_PASSWORD + 1, None, 0, 1, output, 1) == LIMIT
        assert derive(None, 0, b"x", MAX_SALT + 1, 1, output, 1) == LIMIT
    assert output.raw == CANARY

    initial = bytes(range(192))
    alias = C.create_string_buffer(initial, len(initial))
    salt_offset, output_offset, length = 72, 23, 90
    expected = pbkdf2_hmac("sha256", initial[:64], initial[salt_offset:160], 3, length)
    assert derive(alias, 64, C.byref(alias, salt_offset), 160 - salt_offset, 3,
                  C.byref(alias, output_offset), length) == OK
    assert alias.raw == initial[:output_offset] + expected + initial[output_offset + length:]

    return {"rfc7914_vectors": len(rfc_vectors), "oracle_comparisons": comparisons,
            "last_checked_block_index": 256, "length_limit_checks": wide, "oracle": ssl.OPENSSL_VERSION}


def check(compiler, output, hmac):
    library, pin, commands = hmac["build"](
        compiler, output, "abc_pbkdf2_sha256_c", (HERE / "abc_pbkdf2_sha256_c.c",),
        ("-DABC_PBKDF2_SHA256_C_SHARED", "-DABC_PBKDF2_SHA256_C_BUILD"),
    )
    result = check_output([sys.executable, "-B", str(__file__), "--exercise", str(library)], text=True, timeout=90)
    report = {"status": "passed", "hacl_revision": pin["hacl_revision"], "commands": commands,
              "library_sha256": sha256(library.read_bytes()).hexdigest(), "checks": json.loads(result)}
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--exercise", type=Path)
    args = parser.parse_args()
    hmac = runpy.run_path(str(HMAC / "check.py"))
    if args.exercise is not None:
        result = validate(args.exercise, hmac["bind"])
    elif args.output is not None:
        result = check(args.cc, args.output, hmac)
    else:
        with TemporaryDirectory(prefix="abc-c-pbkdf2-") as location:
            result = check(args.cc, Path(location), hmac)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
