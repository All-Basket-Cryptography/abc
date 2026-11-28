"""Build standalone C11 BLAKE2b and check it against shared reference fixtures."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import platform
import runpy
import ssl
from statistics import median
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter


HERE = Path(__file__).resolve().parent
CORE = HERE / "abc_blake2b_c.c"
OK, INVALID_ARGUMENT, INVALID_SIZE, MESSAGE_TOO_LONG = range(4)
CANARY = b"\xa5" * 8
REFERENCE = runpy.run_path(str(HERE.parent / "cpp" / "check.py"))


class Context(ctypes.Structure):
    _fields_ = [("state", ctypes.c_uint64 * 8), ("compressed_low", ctypes.c_uint64),
                ("compressed_high", ctypes.c_uint64), ("used", ctypes.c_size_t),
                ("digest_size", ctypes.c_size_t), ("pending", ctypes.c_uint8 * 128)]


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


class Checks:
    def __init__(self, binary):
        self.library = ctypes.CDLL(str(binary))
        context, buffer, size = ctypes.POINTER(Context), ctypes.c_void_p, ctypes.c_size_t
        self.init = self.bind("init", context, size)
        self.update = self.bind("update", context, buffer, size)
        self.digest = self.bind("digest", context, buffer, size)
        self.one_shot = self.bind("hash", buffer, size, buffer, size)

    def bind(self, name, *args):
        function = getattr(self.library, "abc_blake2b_c_" + name)
        function.argtypes = args
        function.restype = ctypes.c_int
        return function

    def output(self, operation, *args, length):
        buffer = ctypes.create_string_buffer(CANARY + bytes(length) + CANARY, length + 2 * len(CANARY))
        require(operation(*args, ctypes.byref(buffer, len(CANARY)), length) == OK, "digest status")
        require(buffer.raw[:len(CANARY)] == CANARY and buffer.raw[-len(CANARY):] == CANARY, "digest canaries")
        return buffer.raw[len(CANARY):-len(CANARY)]

    def stream(self, message, expected, split, prefix=None):
        size = len(expected)
        context = Context()
        require(self.init(context, size) == OK, "initialize digest size")
        require(self.update(context, message[:split], split) == OK, "absorb prefix")
        if prefix is not None:
            require(self.output(self.digest, context, length=size) == prefix, "prefix snapshot")
        require(self.update(context, None, 0) == OK, "absorb empty input")
        require(self.update(context, message[split:], len(message) - split) == OK, "absorb suffix")
        require(self.output(self.digest, context, length=size) == expected, "stream digest")

    def boundary_errors(self):
        context = Context()
        expected = bytes.fromhex(REFERENCE["reference"](bytes(range(129)), 31))
        require(self.init(None, 31) == INVALID_ARGUMENT, "null context")
        require(self.init(context, 31) == OK, "initialize boundary context")
        original = ctypes.create_string_buffer(bytes(range(128)), 128)
        require(self.update(context, original, 128) == OK, "absorb caller buffer")
        ctypes.memset(original, 0, 128)
        unchanged = bytes(context)
        output = ctypes.create_string_buffer(CANARY * 8, 64)
        require(self.init(context, 0) == INVALID_SIZE and self.init(context, 65) == INVALID_SIZE, "invalid size")
        require(self.update(context, None, 1) == INVALID_ARGUMENT, "invalid input")
        require(self.digest(context, None, 31) == INVALID_ARGUMENT, "invalid output")
        require(self.digest(context, output, 30) == INVALID_SIZE, "short digest buffer")
        require(self.one_shot(None, 1, output, 31) == INVALID_ARGUMENT, "invalid one-shot input")
        require(self.one_shot(None, 0, None, 31) == INVALID_ARGUMENT, "invalid one-shot output")
        require(self.one_shot(None, 0, output, 65) == INVALID_SIZE, "invalid one-shot size")
        require(bytes(context) == unchanged and output.raw == CANARY * 8, "error rollback")
        require(self.update(context, b"\x80", 1) == OK, "continue after buffer reuse and errors")
        require(self.output(self.digest, context, length=31) == expected, "caller data preserved")
        alias = ctypes.create_string_buffer(bytes(range(129)), 129)
        require(self.one_shot(alias, 129, ctypes.byref(alias, 7), 31) == OK, "overlapping one-shot buffers")
        require(alias.raw == bytes(range(7)) + expected + bytes(range(38, 129)), "overlap output extent")
        require(self.init(context, 1) == OK, "reinitialize at another size")
        empty = bytes.fromhex(REFERENCE["reference"](b"", 1))
        require(self.output(self.digest, context, length=1) == empty, "reset snapshot")

        max_word = 2**64 - 1
        context.compressed_low, context.compressed_high, context.used = max_word - 127, 5, 128
        require(self.update(context, b"x", 1) == OK, "carry from a completed block")
        require((context.compressed_low, context.compressed_high, context.used) == (0, 6, 1), "128-bit carry")
        context.compressed_low, context.compressed_high, context.used = max_word - 127, max_word, 126
        require(self.update(context, b"a", 1) == OK and context.used == 127, "maximum byte count")
        unchanged = bytes(context)
        require(self.update(context, b"b", 1) == MESSAGE_TOO_LONG, "128-bit overflow error")
        require(self.update(context, None, 0) == OK and bytes(context) == unchanged, "overflow rollback")

    def verify(self):
        self.boundary_errors()
        counts = dict.fromkeys(("known_answers", "openssl_comparisons", "hashlib_comparisons",
                                "snapshots", "streaming_splits"), 0)
        keys = {"known": "known_answers", "openssl": "openssl_comparisons", "variable": "hashlib_comparisons"}
        fixtures = iter(REFERENCE["fixtures"]())
        for role, input_hex, expected_hex, prefix_hex in zip(fixtures, fixtures, fixtures, fixtures, strict=True):
            message, expected, prefix = map(bytes.fromhex, (input_hex, expected_hex, prefix_hex))
            actual = self.output(self.one_shot, message or None, len(message), length=len(expected))
            require(actual == expected, "one-shot digest")
            counts[keys[role]] += 1
            self.stream(message, expected, len(message) // 2, prefix)
            counts["snapshots"] += 1
            if len(message) <= 257 and len(expected) in (1, 31, 64):
                for split in range(len(message) + 1):
                    self.stream(message, expected, split)
                    counts["streaming_splits"] += 1
        return counts

    def benchmark(self):
        message = bytes((i * 73 + 11) & 0xff for i in range(256)) * 4096
        buffer = ctypes.create_string_buffer(64)

        def native():
            require(self.one_shot(message, len(message), buffer, 64) == OK, "benchmark digest")

        def openssl():
            REFERENCE["reference"](message, 64)

        def batch(operation):
            start = perf_counter()
            for _ in range(16):
                operation()
            return 16 / (perf_counter() - start)

        for _ in range(4):
            native()
            openssl()
        samples = [(batch(native), batch(openssl)) for _ in range(7)]
        c_samples, openssl_samples = zip(*samples, strict=True)
        return {"message_bytes": len(message), "hashes_per_batch": 16, "native_median_mib_s": median(c_samples),
                "openssl_median_mib_s": median(openssl_samples), "host_cpu": platform.processor()}


def build(work, ubsan):
    flags = ["--driver-mode=gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
    if sys.platform == "win32":
        binary = work / "abc_blake2b_c.dll"
        flags.extend(["-shared", "-DABC_BLAKE2B_C_SHARED", "-DABC_BLAKE2B_C_BUILD"])
    else:
        binary = work / ("libabc_blake2b_c.dylib" if sys.platform == "darwin" else "libabc_blake2b_c.so")
        flags.extend(["-dynamiclib" if sys.platform == "darwin" else "-shared", "-fPIC", "-fvisibility=hidden"])
    if ubsan:
        flags.extend(["-fsanitize=undefined", "-fsanitize-trap=undefined"])
    subprocess.run(["clang", *flags, str(CORE), "-o", str(binary)], cwd=work, check=True, timeout=90)
    return binary, flags


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--ubsan", action="store_true")
    mode.add_argument("--benchmark", action="store_true")
    parser.add_argument("--exercise", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.exercise is not None:
        checks = Checks(args.exercise)
        report = {"results": checks.verify()}
        if args.benchmark:
            report["benchmark"] = checks.benchmark()
        print(json.dumps(report))
        return

    with TemporaryDirectory(prefix="abc-blake2b-c-") as directory:
        binary, flags = build(Path(directory), args.ubsan)
        command = [sys.executable, "-B", str(__file__), "--exercise", str(binary)]
        if args.benchmark:
            command.append("--benchmark")
        report = json.loads(subprocess.check_output(command, text=True, timeout=90))
        print(json.dumps({"status": "passed", "flags": flags, "oracle": ssl.OPENSSL_VERSION,
                          "compiler": subprocess.check_output(["clang", "--version"], text=True).splitlines()[:2],
                          "sources_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                             for path in (CORE, CORE.with_suffix(".h"))}, **report}, indent=2))


if __name__ == "__main__":
    main()
