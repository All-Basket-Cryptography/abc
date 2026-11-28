"""Check the portable C11 SHA-512 core against independent OpenSSL digests."""

import argparse
import ctypes
from _hashlib import openssl_sha512
import hashlib
import json
from pathlib import Path
import platform
import random
import ssl
import statistics
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter


HERE = Path(__file__).resolve().parent
DIGEST_BYTES = 64
BLOCK_BYTES = 128
OK, INVALID_ARGUMENT, MESSAGE_TOO_LONG, DESTINATION_TOO_SHORT = range(4)
CANARY = b"\xa5" * 8


class Context(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint64 * 8),
        ("bytes_high", ctypes.c_uint64),
        ("bytes_low", ctypes.c_uint64),
        ("used", ctypes.c_size_t),
        ("pending", ctypes.c_uint8 * BLOCK_BYTES),
    ]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def native_api(library):
    native = ctypes.CDLL(str(library))
    context, buffer, size = ctypes.POINTER(Context), ctypes.c_void_p, ctypes.c_size_t
    definitions = {"init": [context], "update": [context, buffer, size],
                   "digest": [context, buffer, size], "hash": [buffer, size, buffer, size]}
    bound = {}
    for suffix, arguments in definitions.items():
        function = getattr(native, f"abc_sha512_c_{suffix}")
        function.argtypes = arguments
        function.restype = ctypes.c_int
        bound[suffix] = function
    return bound


def fixtures():
    known = [
        (b"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        (b"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),
        (b"a" * 1_000_000, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"),
    ]
    rng = random.Random(1804)
    sizes = [0, 1, 2, 31, 32, 110, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 257,
             383, 384, 511, 512, 1024, 4096, 65536]
    sizes.extend(rng.randrange(4097) for _ in range(128))
    comparisons = [(data, openssl_sha512(data).digest()) for data in map(rng.randbytes, sizes)]
    return [(data, bytes.fromhex(expected)) for data, expected in known], comparisons


def checked_digest(function, args, expected):
    output = ctypes.create_string_buffer(bytes(DIGEST_BYTES) + CANARY, DIGEST_BYTES + len(CANARY))
    require(function(*args, output, len(output)) == OK, "digest status")
    require(output.raw == expected + CANARY, "digest or output suffix")


def boundaries(api):
    init, update, digest, one_shot = (api[name] for name in ("init", "update", "digest", "hash"))
    state = Context()
    require(init(None) == INVALID_ARGUMENT and init(state) == OK, "context validation")
    caller = ctypes.create_string_buffer(b"abc", 3)
    require(update(state, caller, len(caller)) == OK, "initial update")
    ctypes.memset(caller, 0, len(caller))

    before = bytes(state)
    require(update(None, b"x", 1) == INVALID_ARGUMENT, "null context")
    require(update(state, None, 1) == INVALID_ARGUMENT, "null input")
    require(digest(state, None, DIGEST_BYTES) == INVALID_ARGUMENT, "null destination")
    require(bytes(state) == before, "invalid call changed state")
    short = ctypes.create_string_buffer(CANARY, len(CANARY))
    require(digest(state, short, len(short)) == DESTINATION_TOO_SHORT, "short snapshot")
    require(one_shot(b"abc", 3, short, len(short)) == DESTINATION_TOO_SHORT, "short one-shot destination")
    require(short.raw == CANARY, "rejected call changed output")
    full = ctypes.create_string_buffer(CANARY * 8, DIGEST_BYTES)
    require(one_shot(None, 1, full, len(full)) == INVALID_ARGUMENT, "null one-shot input")
    require(full.raw == CANARY * 8, "invalid input changed output")
    checked_digest(digest, (state,), openssl_sha512(b"abc").digest())
    require(update(state, b"d", 1) == OK, "update after rejection")
    checked_digest(digest, (state,), openssl_sha512(b"abcd").digest())

    require(init(state) == OK, "reset")
    checked_digest(digest, (state,), openssl_sha512(b"").digest())
    state.bytes_high, state.bytes_low, state.used = 3, (1 << 64) - 1, 127
    require(update(state, b"x", 1) == OK and (state.bytes_high, state.bytes_low) == (4, 0), "counter carry")
    require(state.used == 0, "completed synthetic block remained buffered")
    state.bytes_high, state.bytes_low, state.used = (1 << 61) - 1, (1 << 64) - 2, 126
    require(update(state, b"x", 1) == OK, "maximum bytes rejected")
    before = bytes(state)
    require(update(state, b"x", 1) == MESSAGE_TOO_LONG, "over-limit input accepted")
    require(update(state, None, 0) == OK, "empty update at limit")
    require(bytes(state) == before, "counter rejection changed state")

    overlap = ctypes.create_string_buffer(b"abc" + bytes(DIGEST_BYTES - 3) + CANARY, DIGEST_BYTES + len(CANARY))
    require(one_shot(overlap, 3, overlap, len(overlap)) == OK, "overlapping input/output")
    require(overlap.raw == openssl_sha512(b"abc").digest() + CANARY, "overlapping result")


def exercise(api):
    init, update, digest, one_shot = (api[name] for name in ("init", "update", "digest", "hash"))
    known, comparisons = fixtures()
    snapshots = splits = 0
    for data, expected in [*known, *comparisons]:
        checked_digest(one_shot, (data or None, len(data)), expected)
        state = Context()
        require(init(state) == OK and update(state, None, 0) == OK, "initialize stream")
        split = len(data) // 2
        require(update(state, data[:split], split) == OK, "first chunk")
        checked_digest(digest, (state,), openssl_sha512(data[:split]).digest())
        snapshots += 1
        require(update(state, data[split:], len(data) - split) == OK, "second chunk")
        checked_digest(digest, (state,), expected)
        if len(data) <= 257:
            for split in range(len(data) + 1):
                require(init(state) == OK, "reset stream")
                require(update(state, data[:split], split) == OK, "split prefix")
                require(update(state, data[split:], len(data) - split) == OK, "split suffix")
                checked_digest(digest, (state,), expected)
                splits += 1
    boundaries(api)
    return {"known_answers": len(known), "comparisons": len(comparisons), "snapshots": snapshots,
            "streaming_splits": splits, "oracle": ssl.OPENSSL_VERSION}


def throughput(one_shot):
    data = bytes(range(256)) * 4096
    output = ctypes.create_string_buffer(DIGEST_BYTES)

    def native():
        require(one_shot(data, len(data), output, len(output)) == OK, "benchmark hash")

    def reference():
        openssl_sha512(data).digest()

    def sample(operation):
        start = perf_counter()
        for _ in range(16):
            operation()
        return 16 / (perf_counter() - start)

    for _ in range(4):
        native()
        reference()
    samples = [tuple(sample(operation) for operation in (native, reference)) for _ in range(7)]
    direct, oracle = map(list, zip(*samples, strict=True))
    return {"message_bytes": len(data), "hashes_per_batch": 16,
            "native_median_mib_s": statistics.median(direct), "native_samples_mib_s": direct,
            "oracle_median_mib_s": statistics.median(oracle), "oracle_samples_mib_s": oracle,
            "host_cpu": platform.processor()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ubsan", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--exercise", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.ubsan and args.benchmark:
        parser.error("Benchmark the uninstrumented build separately")
    if args.exercise is not None:
        api = native_api(args.exercise)
        result = {"checks": exercise(api)}
        if args.benchmark:
            result["benchmark"] = throughput(api["hash"])
        print(json.dumps(result))
        return

    clang = subprocess.check_output(["clang", "--version"], text=True, timeout=15).splitlines()[:2]
    with TemporaryDirectory(prefix="abc-sha512-c-") as scratch:
        extension = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
        library = Path(scratch) / f"abc_sha512_c{extension}"
        source = str(HERE / "abc_sha512_c.c")
        sanitizers = ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"] if args.ubsan else []
        if sys.platform == "win32":
            flags = ["--driver-mode=cl", "/std:c17", "/MD", "/O2", "/W4", "/WX", "/LD",
                     "/DABC_SHA512_C_SHARED", "/DABC_SHA512_C_BUILD"]
            flags.extend("/clang:" + flag for flag in sanitizers)
            build = ["clang", *flags, source, "/Fo:" + str(library.with_suffix(".obj")), "/Fe:" + str(library)]
        else:
            flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                     "-fvisibility=hidden", "-fPIC", *sanitizers]
            link = "-dynamiclib" if sys.platform == "darwin" else "-shared"
            build = ["clang", *flags, link, source, "-o", str(library)]
        subprocess.run(build, check=True, timeout=90)
        child = [sys.executable, "-B", str(__file__), "--exercise", str(library)]
        if args.benchmark:
            child.append("--benchmark")
        result = json.loads(subprocess.check_output(child, text=True, timeout=100))
        report = {"status": "passed", "compiler": clang, "flags": flags,
                  "sources_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                     for name in ("abc_sha512_c.c", "abc_sha512_c.h", "check.py")},
                  **result}
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
