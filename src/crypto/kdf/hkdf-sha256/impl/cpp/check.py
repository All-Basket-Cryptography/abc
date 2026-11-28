"""Check native C++17 HKDF-SHA-256 against RFC 5869 and Python HMAC."""

from hashlib import sha256
import hmac
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


def reference_expand(prk, info, size):
    blocks = []
    previous = b""
    for counter in range(1, (size + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([counter]), "sha256")
        blocks.append(previous)
    return b"".join(blocks)[:size]


def fixtures():
    ikm = b"\x0b" * 22
    cases = [
        (bytes(range(13)), ikm, bytes(range(240, 250)),
         bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
         bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")),
        (b"", ikm, b"",
         bytes.fromhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
         bytes.fromhex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")),
    ]
    random_bytes = random.Random(5869).randbytes
    for salt_size in [0, 1, 32, 64, 65, 129]:
        for size in [0, 1, 31, 32, 33, 63, 64, 65, 127, 8159, 8160]:
            salt, ikm, info = random_bytes(salt_size), random_bytes(size % 101), random_bytes(size % 131)
            prk = hmac.digest(salt, ikm, "sha256")
            cases.append((salt, ikm, info, prk, reference_expand(prk, info, size)))
    info = random_bytes(65)
    for size in [33, 64, 65, 131]:
        prk = random_bytes(size)
        cases.append((b"", b"", info, prk, reference_expand(prk, info, 257)))
    return "".join(f"{part.hex()}\n" for case in cases for part in case)


def main():
    with TemporaryDirectory(prefix="abc-hkdf-cpp-") as directory:
        executable = Path(directory) / ("checks.exe" if os.name == "nt" else "checks")
        run(["clang", *FLAGS, "-I", str(SHA), "-I", str(HMAC), str(SHA / "sha256.cpp"),
             str(HMAC / "hmac_sha256.cpp"), str(HERE / "hkdf_sha256.cpp"), str(HERE / "tests.cpp"),
             "-o", str(executable)])
        report = json.loads(run([str(executable)], input=fixtures()))
    report["compiler"] = run(["clang", "--version"]).splitlines()[:2]
    report["oracle"] = ssl.OPENSSL_VERSION + " via Python hmac"
    report["sources_sha256"] = {
        name: sha256((HERE / name).read_bytes()).hexdigest()
        for name in ("hkdf_sha256.hpp", "hkdf_sha256.cpp", "tests.cpp")
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
