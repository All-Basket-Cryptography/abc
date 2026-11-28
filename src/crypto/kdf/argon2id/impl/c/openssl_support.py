"""Build a native Windows test consumer against a fingerprinted OpenSSL DLL."""

import ctypes
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


PIN = "9325e8486c61b3227abeacf635279a10b828a3b39bc1124a6b5159ae00174181"
GIT_DLL = Path("C:/Program Files/Git/mingw64/bin/libcrypto-3-x64.dll")


def run(args, **kwargs):
    result = subprocess.run(args, text=True, encoding="utf-8", capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def options(parser):
    parser.add_argument("--openssl-dll", type=Path, default=os.environ.get("ABC_OPENSSL_DLL", GIT_DLL))
    parser.add_argument("--dll-sha256", default=os.environ.get("ABC_OPENSSL_DLL_SHA256", PIN))
    parser.add_argument("--openssl-include", type=Path, default=os.environ.get("ABC_OPENSSL_INCLUDE"))
    parser.add_argument("--ubsan", action="store_true")


def load(work):
    if sys.platform != "win32":
        raise ValueError("The qualification adapter expects Windows x64")
    dll = ctypes.CDLL(str(work / "libcrypto-3-x64.dll"))
    version = dll.OpenSSL_version
    version.argtypes = [ctypes.c_int]
    version.restype = ctypes.c_char_p
    return dll, version(0).decode("ascii")


def build(work, args, sources, flags, symbols, cpp=False):
    if sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError("The qualification adapter expects Windows x64")
    if args.openssl_include is None:
        raise ValueError("Select the OpenSSL development include directory with --openssl-include or ABC_OPENSSL_INCLUDE")
    include = Path(args.openssl_include).resolve()
    dll = Path(args.openssl_dll).resolve()
    fingerprint = hashlib.sha256(dll.read_bytes()).hexdigest()
    if fingerprint != args.dll_sha256.lower():
        raise ValueError("The OpenSSL binary SHA-256 differs from the supplied pin")
    shipped = work / "libcrypto-3-x64.dll"
    shutil.copy2(dll, shipped)
    header = (include / "openssl/opensslv.h").read_text(encoding="utf-8")
    macros = dict(re.findall(r"(?m)^#\s*define\s+OPENSSL_VERSION_(MAJOR|MINOR|PATCH)\s+(\d+)\s*$", header))
    version = tuple(int(macros[key]) for key in ("MAJOR", "MINOR", "PATCH"))
    if version[0] != 3 or version < (3, 5, 4):
        raise ValueError(f"Expected OpenSSL headers for 3.5.4 or later in the 3.x series; found {version}")

    exports = work / "crypto.def"
    exports.write_text("LIBRARY libcrypto-3-x64.dll\nEXPORTS\n" + "\n".join(sorted(set(symbols))) + "\n", encoding="ascii")
    import_lib = work / "crypto.lib"
    run(["llvm-dlltool", "-m", "i386:x86-64", "-d", str(exports), "-l", str(import_lib)], cwd=work)
    compiler_flags = ["--driver-mode=g++" if cpp else "--driver-mode=gcc", "-std=c++17" if cpp else "-std=c11",
                      "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-shared", "-I", str(include), *flags]
    if args.ubsan:
        compiler_flags.extend(["-fsanitize=undefined", "-fsanitize-trap=undefined"])
    binary = work / "checks.dll"
    run(["clang", *compiler_flags, *map(str, sources), str(import_lib), "-o", str(binary)], cwd=work)
    return binary, {"dll_sha256": fingerprint, "headers": ".".join(map(str, version)), "ubsan_trap": args.ubsan,
                    "compiler": run(["clang", "--version"]).splitlines()[:2]}
