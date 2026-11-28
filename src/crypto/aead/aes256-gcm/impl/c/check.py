"""Verify independent C11 and C++17 AES-256-GCM against NIST and OpenSSL."""

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
AES = HERE.parents[3] / "cipher/aes256/impl"
REFERENCE = runpy.run_path(str(AES / "java/check.py"))["reference"]
CANARY = b"\xa5"


class Context(ctypes.Structure):
    _fields_ = [("aes", ctypes.c_uint8 * 480), ("hash_high", ctypes.c_uint64), ("hash_low", ctypes.c_uint64)]


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def reject_cases(seal, open_, context, nonce, aad, ciphertext, tag):
    length = len(ciphertext)
    output = ctypes.create_string_buffer(CANARY * length, length)
    for index in range(len(tag)):
        modified = tag[:index] + bytes([tag[index] ^ 1]) + tag[index + 1:]
        require(open_(context, nonce, aad, len(aad), ciphertext, length, modified, output, length) == 3,
                "reject altered tag byte")
        require(output.raw == CANARY * length, "tag failure wrote plaintext")
    for changed_aad, changed_body in ((bytes([aad[0] ^ 1]) + aad[1:], ciphertext),
                                      (aad, bytes([ciphertext[0] ^ 1]) + ciphertext[1:])):
        require(open_(context, nonce, changed_aad, len(aad), changed_body, length, tag, output, length) == 3,
                "reject altered AAD or body")
        require(output.raw == CANARY * length, "AAD or body failure wrote plaintext")
    huge = (1 << 64) - 1
    require(open_(context, nonce, aad, len(aad), ciphertext, huge, tag, output, huge) == 1, "counter limit")
    require(open_(context, nonce, aad, huge, ciphertext, length, tag, output, length) == 1, "AAD length limit")
    require(seal(context, nonce, aad, len(aad), ciphertext, length, output, length, output) == 1,
            "reject shared ciphertext and tag output")
    tag_buffer = ctypes.create_string_buffer(CANARY * 16, 16)
    require(seal(context, nonce, aad, len(aad), ciphertext, length, output, length - 1, tag_buffer) == 1,
            "reject short ciphertext output")
    require(output.raw == CANARY * length and tag_buffer.raw == CANARY * 16, "argument error wrote output")


def check_c(binary, rows):
    lib = ctypes.CDLL(str(binary))
    ptr, size, context_ptr = ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Context)

    def bind(name, args, result=ctypes.c_int):
        function = getattr(lib, "abc_aes256_gcm_c_" + name)
        function.argtypes = [context_ptr, *args]
        function.restype = result
        return function

    init = bind("init", [ptr, size])
    seal = bind("seal", [ptr, ptr, size, ptr, size, ptr, size, ptr])
    open_ = bind("open", [ptr, ptr, size, ptr, size, ptr, ptr, size])
    clear = bind("clear", [], None)
    context = Context()
    negative = aad_overlap = False
    for row in rows:
        key, nonce, aad, plaintext, encrypted, tag = (bytes.fromhex(x) for x in row.split(":"))
        length = len(plaintext)
        require(length == len(encrypted), "independent oracle body length")
        require(init(context, key, 32) == 0, "initialize AES-NI key")
        output = ctypes.create_string_buffer(CANARY * (length + 2), length + 2)
        tag_buffer = ctypes.create_string_buffer(16)
        body = ctypes.byref(output, 1) if length else None
        require(seal(context, nonce, aad or None, len(aad), plaintext or None, length, body, length, tag_buffer) == 0
                and output.raw == CANARY + encrypted + CANARY and tag_buffer.raw == tag, "detached seal")
        require(open_(context, nonce, aad or None, len(aad), encrypted or None, length, tag, body, length) == 0
                and output.raw == CANARY + plaintext + CANARY, "detached open")

        shift = ctypes.create_string_buffer(plaintext + bytes(7), length + 7)
        require(seal(context, nonce, aad or None, len(aad), shift, length, ctypes.byref(shift, 7), length, tag_buffer) == 0
                and shift.raw[7:] == encrypted and tag_buffer.raw == tag, "shifted seal")
        require(open_(context, nonce, aad or None, len(aad), ctypes.byref(shift, 7), length, tag, shift, length) == 0
                and shift.raw[:length] == plaintext, "shifted open")
        if 1 <= len(aad) <= length and not aad_overlap:
            ctypes.memmove(body, aad, len(aad))
            require(seal(context, nonce, body, len(aad), plaintext, length, body, length, tag_buffer) == 0
                    and output.raw == CANARY + encrypted + CANARY and tag_buffer.raw == tag, "AAD aliases output")
            aad_overlap = True
        if aad and length > 16 and not negative:
            reject_cases(seal, open_, context, nonce, aad, encrypted, tag)
            negative = True
    clear(context)
    require(bytes(context) == bytes(ctypes.sizeof(context)), "clear schedule and hash key")
    require(negative and aad_overlap, "incomplete boundary coverage")
    print(len(rows))


def run(command, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def check(language, ubsan):
    reference = REFERENCE("aes256-gcm")
    fixture = "\n".join(reference["output"]) + "\n"
    cpp = language == "cpp"
    leaf = HERE.parent / language
    base = AES / language / ("aes256.cpp" if cpp else "abc_aes256_c.c")
    source = leaf / ("aes256_gcm.cpp" if cpp else "abc_aes256_gcm_c.c")
    flags = ["--driver-mode=g++" if cpp else "--driver-mode=gcc", "-std=c++17" if cpp else "-std=c11",
             "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
    if ubsan:
        flags.extend(["-fsanitize=undefined", "-fsanitize-trap=undefined"])
    with TemporaryDirectory(prefix="abc-aes256-gcm-native-") as directory:
        work = Path(directory)
        if cpp:
            binary = work / ("checks.exe" if sys.platform == "win32" else "checks")
            objects = []
            for item in (base, source):
                output = work / (item.stem + ".o")
                run(["clang", *flags, "-c", str(item), "-o", str(output)])
                objects.append(str(output))
            run(["clang", *flags, str(leaf / "tests.cpp"), *objects, "-o", str(binary)])
            observed = run([str(binary)], input=fixture)
        else:
            if sys.platform == "win32":
                binary = work / "abc_aes256_gcm_c.dll"
                flags.extend(["-shared", "-DABC_AES256_C_BUILD_DLL"])
            else:
                binary = work / ("libabc_aes256_gcm_c.dylib" if sys.platform == "darwin" else "libabc_aes256_gcm_c.so")
                flags.extend(["-dynamiclib" if sys.platform == "darwin" else "-shared", "-fPIC"])
            run(["clang", *flags, str(base), str(source), "-o", str(binary)], cwd=work)
            observed = run([sys.executable, "-B", str(__file__), "--exercise", str(binary)], input=fixture)
        require(int(observed) == 274, "incomplete differential corpus")
        print(json.dumps({"status": "passed", "flags": flags,
                          "source_sha256": {item.name: hashlib.sha256(item.read_bytes()).hexdigest() for item in (base, source)},
                          "compiler": run(["clang", "--version"]).splitlines()[:2], "node": reference["node"],
                          "openssl": reference["openssl"], "known_answers": 2,
                          "bidirectional_comparisons": 272, "authentication_rejections": 18}, indent=2))


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
