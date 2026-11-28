"""Verify the standalone C++17 sequential, unkeyed BLAKE2b module."""

from _hashlib import new as openssl_digest
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import ssl
from statistics import median
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter


HERE = Path(__file__).resolve().parent
FLAGS = ["--driver-mode=g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
KNOWN = [
    (b"abc", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d"
             "87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
    (b"", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d"
          "25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
    (bytes(range(127)), "b6292669ccd38d5f01caae96ba272c76a879a45743afa0725d83b9ebb26665b731"
                        "f1848c52f11972b6644f554c064fa90780dbbbf3a89d4fc31f67df3e5857ef"),
    (bytes(range(128)), "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e8"
                        "ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115"),
    (bytes(range(129)), "f59711d44a031d5f97a9413c065d1e614c417ede998590325f49bad2fd444d3e"
                        "4418be19aec4e11449ac1a57207898bc57d76a1bcf3566292c20c683a5c4648f"),
]


def reference(message, size):
    if size == 64:
        return openssl_digest("blake2b512", message).hexdigest()
    return hashlib.blake2b(message, digest_size=size).hexdigest()


def fixtures():
    def case(role, message, expected):
        return (role, message.hex(), expected, reference(message[:len(message) // 2], len(expected) // 2))

    def comparison(message, size):
        return case("openssl" if size == 64 else "variable", message, reference(message, size))

    for message, expected in KNOWN:
        if reference(message, 64) != expected:
            raise ValueError("OpenSSL differs from a published known answer")
        yield from case("known", message, expected)

    for length in (0, 1, 127, 128, 129, 255, 256, 257, 1000):
        message = bytes((37 * i + 11) & 0xff for i in range(length))
        for size in range(1, 65):
            yield from comparison(message, size)

    rng = random.Random(7693)
    for length in (4096, 65536, *(rng.randrange(4097) for _ in range(128))):
        message = rng.randbytes(length)
        yield from comparison(message, 64)
        yield from comparison(message, rng.randrange(1, 64))


def run(arguments, **kwargs):
    result = subprocess.run(arguments, text=True, encoding="utf-8", capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{arguments[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def benchmark(binary):
    native = json.loads(run([str(binary), "--benchmark"]))
    payload = bytes((i * 73 + 11) & 0xff for i in range(256)) * 4096
    for _ in range(4):
        reference(payload, 64)
    samples = []
    for _ in native:
        start = perf_counter()
        for _ in range(16):
            reference(payload, 64)
        samples.append(16 / (perf_counter() - start))
    return {"message_bytes": len(payload), "hashes_per_batch": 16, "native_median_mib_s": median(native),
            "openssl_median_mib_s": median(samples), "host_cpu": platform.processor()}


def check(ubsan=False, measured=False):
    flags = FLAGS.copy()
    if ubsan:
        flags.extend(["-fsanitize=undefined", "-fno-sanitize-recover=undefined"])
    with TemporaryDirectory(prefix="abc-blake2b-cpp-") as directory:
        folder = Path(directory)
        binary = folder / ("checks.exe" if os.name == "nt" else "checks")
        core = folder / "blake2b.o"
        run(["clang", *flags, "-c", str(HERE / "blake2b.cpp"), "-o", str(core)])
        run(["clang", *flags, str(HERE / "tests.cpp"), str(core), "-o", str(binary)])
        results = json.loads(run([str(binary)], input="\n".join(fixtures()) + "\n"))
        report = {"status": "passed", "compiler": run(["clang", "--version"]).splitlines()[:2],
                  "flags": flags, "target": platform.machine(), "oracle": ssl.OPENSSL_VERSION,
                  "sources_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                     for name in ("blake2b.cpp", "blake2b.hpp", "tests.cpp")}, "results": results}
        if measured:
            report["benchmark"] = benchmark(binary)
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--ubsan", action="store_true")
    mode.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    check(args.ubsan, args.benchmark)
