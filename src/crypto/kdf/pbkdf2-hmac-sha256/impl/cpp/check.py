"""Check native C++17 PBKDF2-HMAC-SHA-256 against RFC 7914 and Python hashlib."""

import hashlib
import json
import os
from pathlib import Path
import random
import ssl
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
SHA = HERE.parents[3] / "hash/sha256/impl/cpp"
HMAC = HERE.parents[3] / "mac/hmac-sha256/impl/cpp"
FLAGS = ["--driver-mode=g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]


def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90, check=False, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def fixtures():
    cases = [
        (b"passwd", b"salt", 1,
         "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
        (b"Password", b"NaCl", 80_000,
         "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"),
    ]
    random_bytes = random.Random(8018).randbytes
    for size in [1, 31, 32, 33, 63, 64, 65, 95, 257]:
        for password_size in [0, 1, 64, 65, 4096]:
            password, salt = random_bytes(password_size), random_bytes(size % 97)
            rounds = size % 17 + 1
            result = hashlib.pbkdf2_hmac("sha256", password, salt, rounds, size)
            cases.append((password, salt, rounds, result.hex()))
    return "".join(f"{password.hex()}\n{salt.hex()}\n{rounds}\n{result}\n"
                   for password, salt, rounds, result in cases)


def main():
    with TemporaryDirectory(prefix="abc-pbkdf2-cpp-") as directory:
        executable = Path(directory) / ("checks.exe" if os.name == "nt" else "checks")
        run(["clang", *FLAGS, "-I", str(SHA), "-I", str(HMAC), str(SHA / "sha256.cpp"),
             str(HMAC / "hmac_sha256.cpp"), str(HERE / "pbkdf2_sha256.cpp"), str(HERE / "tests.cpp"),
             "-o", str(executable)])
        report = json.loads(run([str(executable)], input=fixtures()))
    report["compiler"] = run(["clang", "--version"]).splitlines()[:2]
    report["oracle"] = ssl.OPENSSL_VERSION + " via Python hashlib"
    report["sources_sha256"] = {
        name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        for name in ("pbkdf2_sha256.hpp", "pbkdf2_sha256.cpp", "tests.cpp")
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
