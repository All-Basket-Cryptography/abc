"""Verify independently compiled AES-256 C11 and C++17 AES-NI implementations."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
REFERENCE = runpy.run_path(str(HERE.parent / "java" / "check.py"))["reference"]


class Context(ctypes.Structure):
    _fields_ = [("encrypt_keys", ctypes.c_uint8 * 240), ("decrypt_keys", ctypes.c_uint8 * 240)]


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def check_c(binary, rows):
    lib = ctypes.CDLL(str(binary))
    point, pointer = ctypes.POINTER(Context), ctypes.c_void_p

    def bind(name, args, result=ctypes.c_int):
        function = getattr(lib, "abc_aes256_c_" + name)
        function.argtypes = args
        function.restype = result
        return function

    available = bind("available", [])
    init = bind("init", [point, pointer, ctypes.c_size_t])
    encrypt = bind("encrypt", [point, pointer, pointer])
    decrypt = bind("decrypt", [point, pointer, pointer])
    clear = bind("clear", [point], None)
    require(available() == 1, "AES-NI is required for this conformance run")
    ctx = Context()
    result = ctypes.create_string_buffer(b"\xa5" * 18, 18)
    output = ctypes.byref(result, 1)
    for row in rows:
        key, plain, cipher, expected_enc, expected_dec = (bytes.fromhex(x) for x in row.split(":"))
        require(init(ctx, key, 32) == 0, "C key expansion")
        require(encrypt(ctx, plain, output) == 0 and result.raw == b"\xa5" + expected_enc + b"\xa5", "C encrypt")
        require(decrypt(ctx, cipher, output) == 0 and result.raw == b"\xa5" + expected_dec + b"\xa5", "C decrypt")
        overlap = ctypes.create_string_buffer(plain + bytes(5), 21)
        require(encrypt(ctx, overlap, ctypes.byref(overlap, 5)) == 0 and overlap.raw[5:] == expected_enc,
                "C shifted overlap encrypt")
        require(decrypt(ctx, ctypes.byref(overlap, 5), overlap) == 0 and overlap.raw[:16] == plain,
                "C shifted overlap decrypt")
    original, untouched = bytes(ctx), result.raw
    require(init(ctx, bytes(32), 31) == 1 and init(ctx, None, 32) == 1 and bytes(ctx) == original,
            "C rejected key preserves context")
    require(encrypt(ctx, None, output) == 1 and decrypt(None, bytes(16), output) == 1 and result.raw == untouched,
            "C invalid block input preserves output")
    clear(ctx)
    require(bytes(ctx) == bytes(ctypes.sizeof(ctx)), "C clears expanded key")
    print(len(rows))


def run(command, **kwargs):
    proc = subprocess.run(command, check=True, text=True, capture_output=True, timeout=120, **kwargs)
    return proc.stdout.strip()


def check(language, ubsan):
    reference = REFERENCE("aes256")
    fixture = "\n".join(reference["output"]) + "\n"
    cpp = language == "cpp"
    source = HERE.parent / "cpp" / "aes256.cpp" if cpp else HERE / "abc_aes256_c.c"
    flags = ["--driver-mode=g++" if cpp else "--driver-mode=gcc", "-std=c++17" if cpp else "-std=c11",
             "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
    if ubsan:
        flags.extend(["-fsanitize=undefined", "-fsanitize-trap=undefined"])
    with TemporaryDirectory(prefix="abc-aes256-native-") as directory:
        work = Path(directory)
        if cpp:
            binary = work / ("checks.exe" if sys.platform == "win32" else "checks")
            obj = work / "aes256.o"
            run(["clang", *flags, "-c", str(source), "-o", str(obj)])
            run(["clang", *flags, str(source.with_name("tests.cpp")), str(obj), "-o", str(binary)])
            observed = run([str(binary)], input=fixture)
        else:
            if sys.platform == "win32":
                binary = work / "abc_aes256_c.dll"
                flags.extend(["-shared", "-DABC_AES256_C_BUILD_DLL"])
            else:
                binary = work / ("libabc_aes256_c.dylib" if sys.platform == "darwin" else "libabc_aes256_c.so")
                flags.extend(["-dynamiclib" if sys.platform == "darwin" else "-shared", "-fPIC"])
            run(["clang", *flags, str(source), "-o", str(binary)], cwd=work)
            observed = run([sys.executable, "-B", str(__file__), "--exercise", str(binary)], input=fixture)
        require(int(observed) == 514, "incomplete differential corpus")
        print(json.dumps({"status": "passed", "flags": flags, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                          "compiler": run(["clang", "--version"]).splitlines()[:2], "node": reference["node"],
                          "openssl": reference["openssl"], "known_answers": 2,
                          "independent_enc": 512, "independent_dec": 512}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=["c", "cpp"], default="c")
    parser.add_argument("--ubsan", action="store_true")
    parser.add_argument("--exercise", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.exercise:
        check_c(args.exercise, sys.stdin.read().splitlines())
    else:
        check(args.language, args.ubsan)
