"""Check native C++17 HMAC-SHA-256 with RFC vectors and a Python HMAC oracle."""

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
FLAGS = ["--driver-mode=g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]


def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90, check=False, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def known_answers():
    return [
        (b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    ]


def fixtures():
    cases = known_answers()
    random_bytes = random.Random(5231).randbytes
    sizes = [0, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 257, 1024]
    for key_size in [0, 1, 31, 32, 63, 64, 65, 131, 1024]:
        key = random_bytes(key_size)
        for length in sizes:
            data = random_bytes(length)
            cases.append((key, data, hmac.digest(key, data, "sha256").hex()))
    return "".join(
        f"{key.hex()}\n{data.hex()}\n{tag}\n{hmac.digest(key, data[:len(data)//2], 'sha256').hex()}\n"
        for key, data, tag in cases
    )


def main():
    with TemporaryDirectory(prefix="abc-hmac-cpp-") as directory:
        work = Path(directory)
        executable = work / ("checks.exe" if os.name == "nt" else "checks")
        run(["clang", *FLAGS, "-I", str(SHA), str(SHA / "sha256.cpp"),
             str(HERE / "hmac_sha256.cpp"), str(HERE / "tests.cpp"), "-o", str(executable)])
        report = json.loads(run([str(executable)], input=fixtures()))
    report["compiler"] = run(["clang", "--version"]).splitlines()[:2]
    report["oracle"] = ssl.OPENSSL_VERSION + " via Python hmac"
    report["sources_sha256"] = {
        filename: sha256((HERE / filename).read_bytes()).hexdigest()
        for filename in ("hmac_sha256.hpp", "hmac_sha256.cpp", "tests.cpp")
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
