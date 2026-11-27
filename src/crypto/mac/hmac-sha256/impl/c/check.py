"""Build and exercise native C HMAC-SHA-256 with the pinned HACL* core."""

import argparse
import ctypes as C
from _hashlib import hmac_digest
from hashlib import sha256
import json
from pathlib import Path
import runpy
import ssl
from subprocess import check_output, run
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
SHA = HERE.parents[3] / "hash/sha256/impl/c"
OK, INVALID, LIMIT, TOO_SHORT = 0, 1, 2, 5
MAX_KEY = (1 << 61) - 1
MAX_MESSAGE = MAX_KEY - 64
TAG_BYTES = 32
CANARY = b"\xa5" * 40


def build(compiler, output, name="abc_hmac_sha256_c", extra_sources=(), extra_flags=()):
    output.mkdir(exist_ok=True, parents=True)
    output = output.resolve()
    sha = runpy.run_path(str(SHA / "check.py"))
    pin = sha["verify_upstream"](None, None)
    _, commands = sha["build"](compiler, output)
    extension = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
    library = output / (name + extension)
    kind = "-dynamiclib" if sys.platform == "darwin" else "-shared"
    pic = [] if sys.platform == "win32" else ["-fPIC"]
    command = [compiler, "-std=c11", "-O2", "-fvisibility=hidden", "-Wall", "-Wextra", "-Werror", *pic,
               "-I", str(SHA), "-I", str(HERE), "-DABC_HMAC_SHA256_C_SHARED", "-DABC_HMAC_SHA256_C_BUILD",
               *extra_flags, kind, str(HERE / "abc_hmac_sha256_c.c"), *map(str, extra_sources),
               str(output / "abc-sha256-c.o"), str(output / "hacl-sha2.o"), "-o", str(library)]
    run(command, check=True, timeout=90)
    return library, pin, [*commands, command]


def bind(library, name, arguments, result=C.c_int):
    function = getattr(library, name)
    function.argtypes = arguments
    function.restype = result
    return function


def validate(library):
    if not __debug__:
        raise RuntimeError("The native conformance checks require Python assertions")
    native = C.CDLL(str(library))
    ptr, size = C.c_void_p, C.c_size_t
    new = bind(native, "abc_hmac_sha256_c_new", [ptr, size, C.POINTER(ptr)])
    update = bind(native, "abc_hmac_sha256_c_update", [ptr, ptr, size])
    digest = bind(native, "abc_hmac_sha256_c_digest", [ptr, ptr, size])
    auth = bind(native, "abc_hmac_sha256_c_authenticate", [ptr, size, ptr, size, ptr, size])
    free = bind(native, "abc_hmac_sha256_c_free", [ptr], None)
    output = C.create_string_buffer(CANARY, len(CANARY))
    comparisons = 0
    for key_size in (0, 1, 31, 63, 64, 65, 131):
        key = bytes((i * 11 + 7) % 256 for i in range(key_size))
        for length in (0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 4096):
            message = bytes((i * 29 + 13) % 256 for i in range(length))
            expected = hmac_digest(key, message, "sha256")
            assert auth(key or None, len(key), message or None, length, output, len(output)) == OK
            assert output.raw == expected + CANARY[TAG_BYTES:]
            state = ptr()
            owned_key = C.create_string_buffer(key) if key else None
            assert new(owned_key, len(key), C.byref(state)) == OK and state.value
            try:
                if owned_key is not None:
                    C.memset(owned_key, 0, len(key))
                split = length // 2
                assert update(state, message[:split], split) == OK
                assert digest(state, output, len(output)) == OK
                assert output.raw[:TAG_BYTES] == hmac_digest(key, message[:split], "sha256")
                assert update(state, None, 0) == OK
                assert update(state, message[split:], length - split) == OK
                assert digest(state, output, len(output)) == OK
                assert output.raw == expected + CANARY[TAG_BYTES:]
            finally:
                free(state)
            comparisons += 1

    for key, message, expected in [
        (b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    ]:
        assert auth(key, len(key), message, len(message), output, len(output)) == OK
        assert output.raw[:TAG_BYTES].hex() == expected

    state = ptr(1)
    output.raw = CANARY
    assert new(None, 1, C.byref(state)) == INVALID and state.value == 1
    assert new(None, 0, None) == INVALID
    assert auth(None, 0, None, 1, output, len(output)) == INVALID
    assert auth(None, 0, None, 0, output, 31) == TOO_SHORT
    assert auth(None, 0, None, 0, None, len(output)) == INVALID
    assert update(None, None, 0) == INVALID
    assert digest(None, output, len(output)) == INVALID
    assert output.raw == CANARY
    assert new(b"key", 3, C.byref(state)) == OK
    wide = C.sizeof(C.c_size_t) >= 8
    try:
        assert update(state, b"abc", 3) == OK
        assert digest(state, output, 31) == TOO_SHORT
        assert digest(state, None, len(output)) == INVALID
        assert update(state, None, 1) == INVALID
        if wide:
            assert update(state, b"x", MAX_MESSAGE) == LIMIT
            assert auth(b"x", MAX_KEY + 1, None, 0, output, len(output)) == LIMIT
            assert auth(None, 0, b"x", MAX_MESSAGE + 1, output, len(output)) == LIMIT
        assert output.raw == CANARY
        assert update(state, b"def", 3) == OK
        assert digest(state, output, len(output)) == OK
        assert output.raw == hmac_digest(b"key", b"abcdef", "sha256") + CANARY[TAG_BYTES:]
    finally:
        free(state)
    free(None)

    data = bytes(range(64))
    overlapping = C.create_string_buffer(data, len(data))
    assert auth(b"key", 3, overlapping, len(data), C.byref(overlapping, 16), 32) == OK
    assert overlapping.raw == data[:16] + hmac_digest(b"key", data, "sha256") + data[48:]
    return {"rfc4231_vectors": 2, "oracle_pairs": comparisons, "streaming_snapshots_per_pair": 2,
            "length_limit_checks": wide, "oracle": ssl.OPENSSL_VERSION}


def check(compiler, output):
    library, pin, commands = build(compiler, output)
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
    if args.exercise is not None:
        result = validate(args.exercise)
    elif args.output is not None:
        result = check(args.cc, args.output)
    else:
        with TemporaryDirectory(prefix="abc-c-hmac-") as location:
            result = check(args.cc, Path(location))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
