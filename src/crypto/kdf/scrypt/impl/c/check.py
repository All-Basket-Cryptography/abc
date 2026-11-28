"""Exercise native C and C++ scrypt against RFC 7914 and OpenSSL."""

import argparse
import ctypes as C
import hashlib
from itertools import product
import json
from pathlib import Path
import random
import runpy
import ssl
from statistics import median
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
PBKDF2 = CRYPTO / "kdf/pbkdf2-hmac-sha256/impl"
HMAC = CRYPTO / "mac/hmac-sha256/impl"
SHA256 = CRYPTO / "hash/sha256/impl"
RFC = (
    (b"", b"", 16, 1, 1,
     "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
    (b"password", b"NaCl", 1024, 8, 16,
     "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
    (b"pleaseletmein", b"SodiumChloride", 16384, 8, 1,
     "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"),
)
OK, BAD_PARAMETERS, INVALID_BUFFER, LENGTH_LIMIT, WORKSPACE_TOO_SMALL = range(5)
CANARY = b"\xa5" * 8


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def reference(password, salt, n, r, p, length):
    return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=length, maxmem=64 * 1024**2)


def exercise(binary, language, benchmark):
    native = C.CDLL(str(binary))
    prefix = "abc_scrypt_test_" if language == "cpp" else "abc_scrypt_c_"
    pointer, size, word = C.c_void_p, C.c_size_t, C.c_uint32

    def bind(name, types):
        function = getattr(native, prefix + name)
        function.argtypes = types
        function.restype = C.c_int
        return function

    workspace_bytes = bind("workspace_bytes", [size, word, word, C.POINTER(size)])
    derive = bind("derive", [pointer, size, pointer, size, size, word, word, pointer, size, pointer, size])

    def check_case(password, salt, n, r, p, expected):
        needed = size()
        require(workspace_bytes(n, r, p, C.byref(needed)) == OK and needed.value == (n + p + 1) * 128 * r,
                "workspace layout")
        space = C.create_string_buffer(CANARY + b"x" * needed.value + CANARY, needed.value + 16)
        output = C.create_string_buffer(CANARY + b"x" * len(expected) + CANARY, len(expected) + 16)
        require(derive(password or None, len(password), salt or None, len(salt), n, r, p,
                       C.byref(space, 8), needed.value + 8, C.byref(output, 8), len(expected)) == OK,
                f"derive N={n}, r={r}, p={p}")
        require(space.raw == CANARY + bytes(needed.value) + CANARY, "workspace wipe and guard bytes")
        require(output.raw == CANARY + expected + CANARY, "independent digest and guard bytes")

    for password, salt, n, r, p, hex_digest in RFC:
        expected = bytes.fromhex(hex_digest)
        require(reference(password, salt, n, r, p, 64) == expected, "RFC oracle")
        check_case(password, salt, n, r, p, expected)

    rng = random.Random(7914)
    comparisons = 0
    for n, r, p, length in product((16, 32, 128, 512), (1, 2, 4, 8), (1, 2, 3), (1, 33, 64)):
        password = rng.randbytes(rng.choice((0, 31, 64, 65, 133, 4096)))
        salt = rng.randbytes(rng.choice((0, 16, 64, 129)))
        check_case(password, salt, n, r, p, reference(password, salt, n, r, p, length))
        comparisons += 1

    needed = size(123)
    for n, r, p in ((0, 1, 1), (1, 1, 1), (3, 1, 1), (16, 0, 1), (16, 1, 0), (1 << 16, 1, 1),
                    (16, 1 << 29, 2), (16, 2, 1 << 29)):
        require(workspace_bytes(n, r, p, C.byref(needed)) == BAD_PARAMETERS and needed.value == 123,
                "parameter preflight preserves receipt")
    huge = 1 << (8 * C.sizeof(size) - 2)
    require(workspace_bytes(huge, 4, 1, C.byref(needed)) == LENGTH_LIMIT and needed.value == 123,
            "overflow preflight preserves receipt")
    require(workspace_bytes(16, 1, 1, None) == INVALID_BUFFER, "null size receipt")
    block = 18 * 128
    space = C.create_string_buffer(b"x" * block, block)
    output = C.create_string_buffer(CANARY, len(CANARY))
    require(derive(None, 0, None, 0, 16, 1, 1, space, block - 1, output, len(output)) == WORKSPACE_TOO_SMALL,
            "short workspace")
    require(derive(space, 1, None, 0, 16, 1, 1, space, block, output, len(output)) == INVALID_BUFFER,
            "overlapping password and workspace")
    require(derive(None, 0, C.byref(space, 1), 1, 16, 1, 1, space, block, output, len(output)) == INVALID_BUFFER,
            "overlapping salt and workspace")
    require(derive(None, 0, None, 0, 16, 1, 1, space, block, space, len(output)) == INVALID_BUFFER,
            "overlapping output and workspace")
    require(derive(None, 1, None, 0, 16, 1, 1, space, block, output, len(output)) == INVALID_BUFFER,
            "nonempty null password")
    require(derive(None, 0, None, 0, 16, 1, 1, space, block, output, 0) == LENGTH_LIMIT, "zero output")
    require(output.raw == CANARY and space.raw == b"x" * block, "preflight preserved buffers")

    shared = C.create_string_buffer(bytes(range(128)), 128)
    expected = reference(bytes(range(43)), bytes(range(48, 96)), 16, 1, 1, 64)
    require(derive(shared, 43, C.byref(shared, 48), 48, 16, 1, 1, space, block, C.byref(shared, 23), 64) == OK,
            "output aliases both inputs")
    require(shared.raw == bytes(range(23)) + expected + bytes(range(87, 128)), "aliased output extent")
    report = {"known_answers": len(RFC), "openssl_comparisons": comparisons, "workspace_preflight": "passed"}
    if benchmark:
        n, r, p, length = 4096, 8, 1, 64
        space = C.create_string_buffer((n + p + 1) * 128 * r)
        output = C.create_string_buffer(length)
        password, salt = b"benchmark", b"abc-scrypt-benchmark"

        def ours():
            require(derive(password, len(password), salt, len(salt), n, r, p, space, len(space), output, length) == OK,
                    "benchmark derive")

        def openssl():
            reference(password, salt, n, r, p, length)

        def batch(operation):
            start = perf_counter()
            for _ in range(4):
                operation()
            return (perf_counter() - start) * 250

        ours()
        openssl()
        direct, baseline = zip(*[(batch(ours), batch(openssl)) for _ in range(5)], strict=True)
        report["benchmark"] = {"n": n, "r": r, "p": p, "workspace_bytes": len(space),
                               "native_median_ms": median(direct), "openssl_median_ms": median(baseline)}
    print(json.dumps(report))


def build_artifact(compiler, work, language, ubsan):
    library = work / ("scrypt.dll" if sys.platform == "win32" else "scrypt.dylib" if sys.platform == "darwin" else "scrypt.so")
    sanitizer = ["-fsanitize=undefined", "-fsanitize-trap=undefined"] if ubsan else []
    if language == "c":
        builder = runpy.run_path(str(HMAC / "c/check.py"))["build"]
        source = HERE / "abc_scrypt_c.c"
        library, pin, _ = builder(compiler, work, "abc_scrypt_c", (PBKDF2 / "c/abc_pbkdf2_sha256_c.c", source),
                                  ("-I", str(PBKDF2 / "c"), "-DABC_SCRYPT_C_BUILD_DLL", *sanitizer))
        return library, source, {"hacl_revision": pin["hacl_revision"]}

    leaf = HERE.parent / "cpp"
    source = leaf / "scrypt.cpp"
    flags = ["--driver-mode=g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-fvisibility=hidden"]
    if sys.platform != "win32":
        flags.append("-fPIC")
    link = "-dynamiclib" if sys.platform == "darwin" else "-shared"
    sources = [SHA256 / "cpp/sha256.cpp", HMAC / "cpp/hmac_sha256.cpp", PBKDF2 / "cpp/pbkdf2_sha256.cpp",
               source, leaf / "tests.cpp"]
    includes = [f"-I{root / 'cpp'}" for root in (SHA256, HMAC, PBKDF2)]
    subprocess.run([compiler, *flags, *sanitizer, *includes, link, *map(str, sources), "-o", str(library)],
                   cwd=work, check=True, capture_output=True, timeout=90)
    return library, source, {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("c", "cpp"), default="c")
    parser.add_argument("--cc", default="clang")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--ubsan", action="store_true")
    mode.add_argument("--benchmark", action="store_true")
    parser.add_argument("--exercise", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.exercise:
        exercise(args.exercise, args.language, args.benchmark)
        return
    with TemporaryDirectory(prefix="abc-scrypt-native-") as scratch:
        library, source, backend = build_artifact(args.cc, Path(scratch), args.language, args.ubsan)
        command = [sys.executable, "-B", str(__file__), "--language", args.language, "--exercise", str(library)]
        if args.benchmark:
            command.append("--benchmark")
        result = subprocess.check_output(command, text=True, timeout=100)
        compiler = subprocess.check_output([args.cc, "--version"], text=True, timeout=15)
        print(json.dumps({"status": "passed", "compiler": compiler.splitlines()[:2], "oracle": ssl.OPENSSL_VERSION,
                          "ubsan_trap": args.ubsan, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                          **backend, **json.loads(result)}, indent=2))


if __name__ == "__main__":
    main()
