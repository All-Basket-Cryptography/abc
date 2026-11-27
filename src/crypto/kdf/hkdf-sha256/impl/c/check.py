"""Build native C HKDF-SHA-256 and compare it with RFC 5869 and OpenSSL."""

import argparse
import ctypes as C
from _hashlib import hmac_digest
from hashlib import sha256
import json
from pathlib import Path
import runpy
import ssl
from subprocess import check_output
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
HMAC = HERE.parents[3] / "mac/hmac-sha256/impl/c"
OK, INVALID, LIMIT, OUTPUT_TOO_SHORT, PRK_TOO_SHORT, OUTPUT_TOO_LONG = 0, 1, 2, 5, 6, 7
HASH_BYTES = 32
MAX_OUTPUT = 255 * HASH_BYTES
MAX_KEY = (1 << 61) - 1
MAX_MESSAGE = MAX_KEY - 64
CANARY = b"\xa5" * 16


def oracle_expand(prk, info, length):
    blocks = []
    previous = b""
    for counter in range(1, (length + HASH_BYTES - 1) // HASH_BYTES + 1):
        previous = hmac_digest(prk, previous + info + bytes([counter]), "sha256")
        blocks.append(previous)
    return b"".join(blocks)[:length]


def validate(library, bind):
    if not __debug__:
        raise RuntimeError("The native conformance checks require Python assertions")
    native = C.CDLL(str(library))
    ptr, size = C.c_void_p, C.c_size_t
    extract = bind(native, "abc_hkdf_sha256_c_extract", [ptr, size] * 3)
    expand = bind(native, "abc_hkdf_sha256_c_expand", [ptr, size] * 3)
    derive = bind(native, "abc_hkdf_sha256_c_derive", [ptr, size] * 4)

    def expect(function, arguments, expected, capacity):
        initial = b"\xa5" * capacity + CANARY
        guarded = C.create_string_buffer(initial, len(initial))
        assert function(*arguments, guarded, capacity) == OK
        assert guarded.raw == expected + initial[len(expected):]

    vectors = (
        (
            bytes(range(13)), b"\x0b" * 22, bytes(range(0xF0, 0xFA)),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            bytes(range(0x60, 0xB0)), bytes(range(0x50)), bytes(range(0xB0, 0x100)),
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac782727"
            "1cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
        (
            b"", b"\x0b" * 22, b"",
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    )
    for salt, ikm, info, prk_hex, okm_hex in vectors:
        prk, okm = bytes.fromhex(prk_hex), bytes.fromhex(okm_hex)
        expect(extract, (salt or None, len(salt), ikm, len(ikm)), prk, HASH_BYTES + 3)
        expect(expand, (prk, len(prk), info or None, len(info)), okm, len(okm))
        expect(derive, (salt or None, len(salt), ikm, len(ikm), info or None, len(info)), okm, len(okm))

    direct = 0
    info = bytes(range(211))
    for key_length in (32, 64, 65, 137):
        key = bytes(range(key_length))
        for length in (0, 1, 31, 32, 33, 63, 64, 65, 97, 8159, 8160):
            expect(expand, (key, key_length, info, len(info)), oracle_expand(key, info, length), length)
            direct += 1

    derivations = 0
    for salt_length in (0, 1, 32, 64, 65, 147):
        salt = bytes(range(salt_length))
        for ikm_length in (0, 1, 32, 64, 65, 149):
            ikm = bytes(range(ikm_length))
            prk = hmac_digest(salt or bytes(HASH_BYTES), ikm, "sha256")
            expect(extract, (salt, salt_length, ikm, ikm_length), prk, HASH_BYTES)
            expect(derive, (salt, salt_length, ikm, ikm_length, info, len(info)),
                   oracle_expand(prk, info, 71), 71)
            derivations += 1

    key = bytes(range(HASH_BYTES))
    output = C.create_string_buffer(CANARY, len(CANARY))
    assert expand(key, len(key), None, 0, None, 0) == OK
    assert derive(None, 0, None, 0, None, 0, None, 0) == OK
    assert extract(None, 1, None, 0, output, HASH_BYTES) == INVALID
    assert extract(None, 0, None, 1, output, HASH_BYTES) == INVALID
    assert extract(None, 0, None, 0, output, HASH_BYTES - 1) == OUTPUT_TOO_SHORT
    assert extract(None, 0, None, 0, None, HASH_BYTES) == INVALID
    assert expand(key, len(key) - 1, None, 0, output, 1) == PRK_TOO_SHORT
    assert expand(None, 0, None, 0, output, 1) == INVALID
    assert expand(key, len(key), None, 1, output, 0) == INVALID
    assert expand(key, len(key), None, 0, None, 1) == INVALID
    assert expand(key, len(key), None, 0, output, MAX_OUTPUT + 1) == OUTPUT_TOO_LONG
    assert derive(None, 1, None, 0, None, 0, output, 1) == INVALID
    assert derive(None, 0, None, 0, None, 0, output, MAX_OUTPUT + 1) == OUTPUT_TOO_LONG
    wide = C.sizeof(size) >= 8
    if wide:
        assert expand(key, MAX_KEY + 1, None, 0, output, 1) == LIMIT
        assert expand(key, len(key), b"x", MAX_MESSAGE, output, 1) == LIMIT
        assert expand(key, len(key), b"x", MAX_MESSAGE - 32, output, 33) == LIMIT
        assert derive(b"x", MAX_KEY + 1, None, 0, None, 0, output, 1) == LIMIT
        assert derive(None, 0, b"x", MAX_MESSAGE + 1, None, 0, output, 1) == LIMIT
    assert output.raw == CANARY

    initial = bytes(range(192))
    alias = C.create_string_buffer(initial, len(initial))
    offset, length = 23, 73
    expected = oracle_expand(initial[:64], initial[64:160], length)
    assert expand(alias, 64, C.byref(alias, 64), 96, C.byref(alias, offset), length) == OK
    assert alias.raw == initial[:offset] + expected + initial[offset + length:]

    return {"rfc5869_vectors": len(vectors), "oracle_expansions": direct,
            "oracle_extract_and_derive_pairs": derivations, "max_output_bytes": MAX_OUTPUT,
            "length_limit_checks": wide, "oracle": ssl.OPENSSL_VERSION}


def check(compiler, output, hmac):
    library, pin, commands = hmac["build"](
        compiler, output, "abc_hkdf_sha256_c", (HERE / "abc_hkdf_sha256_c.c",),
        ("-DABC_HKDF_SHA256_C_SHARED", "-DABC_HKDF_SHA256_C_BUILD"),
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
        with TemporaryDirectory(prefix="abc-c-hkdf-") as location:
            result = check(args.cc, Path(location), hmac)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
