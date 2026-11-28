"""Compile and verify the portable C++ Keccak, SHA3-256, and SHAKE256 profiles."""

import argparse
from _hashlib import openssl_sha3_256, openssl_shake_256
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import ssl
import statistics
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter


HERE = Path(__file__).resolve().parent
HASH_ROOT = HERE.parents[2]
FLAGS = ["--driver-mode=g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
ZERO_ANSWER = (
    0xF1258F7940E1DDE7, 0x84D5CCF933C0478A, 0xD598261EA65AA9EE, 0xBD1547306F80494D, 0x8B284E056253D057,
    0xFF97A42D7F8E6FD4, 0x90FEE5A0A44647C4, 0x8C5BDA0CD6192E76, 0xAD30A6F71B19059C, 0x30935AB7D08FFC64,
    0xEB5AA93F2317D635, 0xA9A6E6260D712103, 0x81A57C16DBCF555F, 0x43B831CD0347C826, 0x01F22F1A11A5569F,
    0x05E5635A21D9AE61, 0x64BEFEF28CC970F2, 0x613670957BC46611, 0xB87C5A554FD00ECB, 0x8C3EE88A1CCF32C8,
    0x940C7922AE3A2614, 0x1841F924A2C509E4, 0x16F53526E70465C2, 0x75F644E97F30A13B, 0xEAF1FF7B5CECA249,
)
ROTATION = (0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)


def permutation_reference(raw):
    def rot_left(word, offset):
        return ((word << offset) | (word >> (64 - offset))) & ((1 << 64) - 1)

    state = [int.from_bytes(raw[i:i + 8], "little") for i in range(0, 200, 8)]
    register = 1
    for _ in range(24):
        columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        delta = [columns[(x - 1) % 5] ^ rot_left(columns[(x + 1) % 5], 1) for x in range(5)]
        projected = [0] * 25
        for y in range(5):
            for x in range(5):
                i = x + 5 * y
                projected[y + 5 * ((2 * x + 3 * y) % 5)] = rot_left(state[i] ^ delta[x], ROTATION[i])
        for y in range(5):
            row = projected[5 * y:5 * (y + 1)]
            for x in range(5):
                state[x + 5 * y] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5])
        # FIPS 202 Algorithm 5 LFSR, advanced seven bits per round.
        for bit in range(7):
            if register & 1:
                state[0] ^= 1 << ((1 << bit) - 1)
            register = ((register << 1) ^ (0x71 if register & 0x80 else 0)) & 0xFF
    return b"".join(value.to_bytes(8, "little") for value in state)


def permutations():
    zero = bytes(200)
    published = b"".join(value.to_bytes(8, "little") for value in ZERO_ANSWER)
    if permutation_reference(zero) != published:
        raise ValueError("The permutation oracle disagrees with the XKCP zero-state answer")
    yield "known", zero, published, b""
    rng = random.Random(1600)
    for _ in range(128):
        state = rng.randbytes(200)
        yield "comparison", state, permutation_reference(state), b""


def digest(profile, message, length):
    if profile == "sha3-256":
        return openssl_sha3_256(message).digest()
    return openssl_shake_256(message).digest(length)


def hash_cases(profile):
    if profile == "sha3-256":
        known = [
            (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            (b"\xa3" * 200, "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"),
        ]
    else:
        known = [
            (b"", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
            (b"abc", "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"),
            (b"\xa3" * 200, "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d"
                           "2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b"),
        ]
    for message, expected_hex in known:
        expected = bytes.fromhex(expected_hex)
        if digest(profile, message, len(expected)) != expected:
            raise ValueError("The OpenSSL oracle disagrees with a known answer")
        yield "known", message, expected, digest(profile, message[:len(message) // 2], len(expected))

    rng = random.Random(202)
    lengths = [0, 1, 7, 8, 9, 133, 134, 135, 136, 137, 138, 270, 271, 272, 273, 407, 408, 409, 1024, 4096, 65536]
    default = 32 if profile == "sha3-256" else 409
    sizes = [(length, default) for length in lengths]
    if profile == "shake256":
        output_lengths = [0, 1, 7, 8, 9, 134, 135, 136, 137, 271, 272, 273, 409, 1024, 4097]
        sizes.extend((length, output) for length in (0, 137) for output in output_lengths)
        sizes.extend((rng.randrange(4097), rng.randrange(4097)) for _ in range(128))
    else:
        sizes.extend((rng.randrange(4097), default) for _ in range(128))
    for input_length, output_length in sizes:
        message = rng.randbytes(input_length)
        expected = digest(profile, message, output_length)
        yield "comparison", message, expected, digest(profile, message[:input_length // 2], output_length)


def fixtures(profile):
    cases = permutations() if profile == "keccak-p1600" else hash_cases(profile)
    lines = (line for role, input_, expected, prefix in cases
             for line in (role, input_.hex(), expected.hex(), prefix.hex()))
    return "\n".join(lines) + "\n"


def run(args, **kwargs):
    result = subprocess.run(args, text=True, encoding="utf-8", capture_output=True, timeout=180, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def benchmark(profile, consumer):
    native = json.loads(run([str(consumer), "--benchmark"]))
    payload = bytes((i * 73 + 11) & 0xFF for i in range(256)) * 4096
    output_length = 32 if profile == "sha3-256" else 4096
    for _ in range(4):
        digest(profile, payload, output_length)
    reference = []
    for _ in native:
        start = perf_counter()
        for _ in range(16):
            digest(profile, payload, output_length)
        reference.append(16 / (perf_counter() - start))
    return {"message_bytes": len(payload), "output_bytes": output_length, "hashes_per_batch": 16,
            "native_median_mib_s": statistics.median(native), "oracle_median_mib_s": statistics.median(reference),
            "native_samples_mib_s": native, "oracle_samples_mib_s": reference, "host_cpu": platform.processor()}


def check(profile, ubsan, measured):
    flags = FLAGS.copy()
    if ubsan:
        flags.extend(["-fsanitize=undefined", "-fno-sanitize-recover=undefined"])
    with TemporaryDirectory(prefix="abc-keccak-cpp-") as directory:
        work = Path(directory)
        core = HERE / "keccak_p1600.cpp"
        leaf = HASH_ROOT / profile / "impl/cpp"
        sources = [core]
        headers = [HERE / "keccak_p1600.hpp", HERE / "test_support.hpp"]
        if profile != "keccak-p1600":
            stem = profile.replace("-", "_")
            sources.append(leaf / (stem + ".cpp"))
            headers.append(leaf / (stem + ".hpp"))
        objects = []
        for source in sources:
            obj = work / (source.stem + ".o")
            run(["clang", *flags, "-c", str(source), "-o", str(obj)])
            objects.append(str(obj))
        consumer = work / ("checks.exe" if os.name == "nt" else "checks")
        tests = leaf / "tests.cpp"
        run(["clang", *flags, str(tests), *objects, "-o", str(consumer)])
        result = json.loads(run([str(consumer)], input=fixtures(profile)))
        report = {"status": "passed", "profile": profile, "compiler": run(["clang", "--version"]).splitlines()[:2],
                  "flags": flags, "sources_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                                    for path in [*sources, *headers, tests]},
                  "checks": result,
                  "oracle": "Independent FIPS 202 arithmetic and XKCP KAT"
                  if profile == "keccak-p1600" else ssl.OPENSSL_VERSION + " via CPython"}
        if measured:
            report["benchmark"] = benchmark(profile, consumer)
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=["keccak-p1600", "sha3-256", "shake256"])
    parser.add_argument("--ubsan", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    if args.benchmark and (args.ubsan or args.profile == "keccak-p1600"):
        parser.error("Benchmark SHA3-256 or SHAKE256 without UBSan")
    print(json.dumps(check(args.profile, args.ubsan, args.benchmark), indent=2))
