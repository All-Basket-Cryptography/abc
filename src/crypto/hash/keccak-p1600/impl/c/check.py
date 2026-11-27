"""Verify the native C Keccak, SHA3-256, and SHAKE256 implementations."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import platform
import ssl
import statistics
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter


HERE = Path(__file__).resolve().parent
HASH_ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent / "cpp"))
from check import digest as reference_digest, hash_cases, permutations


OK, INVALID_ARGUMENT, DESTINATION_TOO_SHORT = range(3)
CANARY = b"\xa5" * 8


class State(ctypes.Structure):
    _fields_ = [("lanes", ctypes.c_uint64 * 25), ("offset", ctypes.c_size_t)]


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def bind(library, name, args, result=ctypes.c_int):
    function = getattr(library, "abc_" + name)
    function.argtypes = args
    function.restype = result
    return function


def check_permutation(library):
    apply = bind(library, "keccak_p1600_c_permute", [ctypes.POINTER(ctypes.c_uint64)], None)
    counts = {"known_answers": 0, "comparisons": 0}
    for role, raw, expected, _ in permutations():
        lanes = (ctypes.c_uint64 * 25)(*(int.from_bytes(raw[i:i + 8], "little") for i in range(0, 200, 8)))
        apply(lanes)
        result = b"".join(word.to_bytes(8, "little") for word in lanes)
        require(result == expected, "Keccak permutation output")
        counts["known_answers" if role == "known" else "comparisons"] += 1
    return counts


class HashChecks:
    def __init__(self, library, profile):
        self.shake = profile == "shake256"
        stem = profile.replace("-", "_") + "_c_"
        point, buffer, size = ctypes.POINTER(State), ctypes.c_void_p, ctypes.c_size_t
        self.init = bind(library, stem + "init", [point])
        self.update = bind(library, stem + "update", [point, buffer, size])
        self.one_shot = bind(library, stem + ("xof" if self.shake else "hash"), [buffer, size, buffer, size])
        if self.shake:
            self.finish = bind(library, stem + "finalize", [point, point])
            self.read = bind(library, stem + "read", [point, buffer, size])
        else:
            self.digest = bind(library, stem + "digest", [point, buffer, size])

    def snapshot(self, state, output_length, split=False):
        output = ctypes.create_string_buffer(bytes(output_length) + CANARY, output_length + len(CANARY))
        if self.shake:
            reader = State()
            require(self.finish(state, reader) == OK, "SHAKE finalize")
            if split:
                cursor = 0
                for count in (0, 1, 7, 127, 1, 136, 137, 4096):
                    amount = min(count, output_length - cursor)
                    require(self.read(reader, None, 0) == OK, "empty SHAKE read")
                    require(self.read(reader, ctypes.byref(output, cursor), amount) == OK, "split SHAKE read")
                    cursor += amount
                require(cursor == output_length, "test split schedule too short")
            else:
                require(self.read(reader, output, output_length) == OK, "SHAKE read")
        else:
            require(self.digest(state, output, len(output)) == OK, "SHA3 digest")
        require(output.raw[output_length:] == CANARY, "snapshot output changed canary")
        return output.raw[:output_length]

    def stream(self, data, expected, split, prefix=None):
        state = State()
        require(self.init(state) == OK, "initialize")
        require(self.update(state, data[:split], split) == OK, "absorb prefix")
        if prefix is not None:
            require(self.snapshot(state, len(expected)) == prefix, "prefix snapshot")
        require(self.update(state, None, 0) == OK, "empty input")
        require(self.update(state, data[split:], len(data) - split) == OK, "absorb suffix")
        require(self.snapshot(state, len(expected), split=True) == expected, "stream result")
        require(self.snapshot(state, len(expected)) == expected, "independent snapshot")

    def boundary_errors(self, profile):
        state = State()
        source = ctypes.create_string_buffer(b"abc", 3)
        expected = reference_digest(profile, b"abc", 409)
        require(self.init(None) == INVALID_ARGUMENT and self.init(state) == OK, "init argument")
        require(self.update(state, source, len(source)) == OK, "caller-buffer input")
        ctypes.memset(source, 0, len(source))
        original = bytes(state)
        require(self.update(state, None, 1) == INVALID_ARGUMENT, "NULL nonempty input")
        require(bytes(state) == original, "invalid update changed the state")
        require(self.snapshot(state, len(expected)) == expected, "caller data was retained")
        require(self.init(state) == OK, "reset")
        require(self.snapshot(state, len(expected)) == reference_digest(profile, b"", len(expected)), "reset state")

        alias = ctypes.create_string_buffer(b"abc" + bytes(len(expected) - 3) + CANARY, len(expected) + len(CANARY))
        require(self.one_shot(alias, 3, alias, len(expected)) == OK, "one-shot input and output alias")
        require(alias.raw == expected + CANARY, "aliased result")
        if self.shake:
            reader = State()
            require(self.update(state, b"abc", 3) == OK and self.finish(state, reader) == OK, "reader validation setup")
            before = bytes(reader)
            require(self.read(reader, None, 1) == INVALID_ARGUMENT, "NULL nonempty output")
            require(self.read(reader, None, 0) == OK and bytes(reader) == before, "rejected read advanced state")
            require(self.one_shot(None, 0, None, 0) == OK, "zero length XOF")
        else:
            before = alias.raw
            require(self.digest(state, alias, len(expected) - 1) == DESTINATION_TOO_SHORT, "short destination")
            require(self.one_shot(b"abc", 3, alias, len(expected) - 1) == DESTINATION_TOO_SHORT, "short one-shot destination")
            require(alias.raw == before, "short destination changed memory")

    def exercise(self, profile):
        counts = {"known_answers": 0, "comparisons": 0, "snapshots": 0, "streaming_splits": 0}
        for role, data, expected, prefix in hash_cases(profile):
            output = ctypes.create_string_buffer(bytes(len(expected)) + CANARY, len(expected) + len(CANARY))
            size = len(expected) if self.shake else len(output)
            require(self.one_shot(data or None, len(data), output, size) == OK, "one-shot status")
            require(output.raw == expected + CANARY, "one-shot result")
            counts["known_answers" if role == "known" else "comparisons"] += 1
            self.stream(data, expected, len(data) // 2, prefix)
            counts["snapshots"] += 1
            if len(data) <= 273 and len(expected) <= 512:
                for split in range(len(data) + 1):
                    self.stream(data, expected, split)
                    counts["streaming_splits"] += 1
        self.boundary_errors(profile)
        return counts

    def benchmark(self, profile):
        message = bytes((i * 73 + 11) & 255 for i in range(256)) * 4096
        output_length = 4096 if self.shake else 32
        output = ctypes.create_string_buffer(output_length)

        def native():
            require(self.one_shot(message, len(message), output, output_length) == OK, "benchmark hash")

        def reference():
            reference_digest(profile, message, output_length)

        def batch(operation):
            start = perf_counter()
            for _ in range(16):
                operation()
            return 16 / (perf_counter() - start)

        for _ in range(4):
            native()
            reference()
        samples = [tuple(batch(operation) for operation in (native, reference)) for _ in range(7)]
        direct, oracle = map(list, zip(*samples, strict=True))
        return {"message_bytes": len(message), "output_bytes": output_length, "host_cpu": platform.processor(),
                "native_median_mib_s": statistics.median(direct), "oracle_median_mib_s": statistics.median(oracle),
                "native_samples_mib_s": direct, "oracle_samples_mib_s": oracle}


def build(profile, work, ubsan):
    core = HERE / "abc_keccak_p1600_c.c"
    files = [core]
    if profile != "keccak-p1600":
        files.append(HASH_ROOT / profile / "impl/c" / f"abc_{profile.replace('-', '_')}_c.c")
    sanitizers = ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"] if ubsan else []
    sources = list(map(str, files))
    if sys.platform == "win32":
        library = work / "abc_keccak_c.dll"
        flags = ["--driver-mode=cl", "/std:c17", "/MD", "/O2", "/W4", "/WX", "/LD",
                 "/DABC_KECCAK_C_SHARED", "/DABC_KECCAK_C_BUILD"]
        flags.extend("/clang:" + flag for flag in sanitizers)
        command = ["clang", *flags, *sources, "/Fe:" + str(library)]
    else:
        library = work / ("libabc_keccak_c.dylib" if sys.platform == "darwin" else "libabc_keccak_c.so")
        flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                 "-fvisibility=hidden", "-fPIC", *sanitizers]
        command = ["clang", *flags, "-dynamiclib" if sys.platform == "darwin" else "-shared",
                   *sources, "-o", str(library)]
    subprocess.run(command, cwd=work, check=True, timeout=90)
    return library, flags, [*files, *(path.with_suffix(".h") for path in files)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=["keccak-p1600", "sha3-256", "shake256"])
    parser.add_argument("--ubsan", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--exercise", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.benchmark and (args.ubsan or args.profile == "keccak-p1600"):
        parser.error("Benchmark SHA3-256 or SHAKE256 without UBSan")
    if args.exercise is not None:
        library = ctypes.CDLL(str(args.exercise))
        if args.profile == "keccak-p1600":
            print(json.dumps({"checks": check_permutation(library)}))
        else:
            checker = HashChecks(library, args.profile)
            result = {"checks": checker.exercise(args.profile)}
            if args.benchmark:
                result["benchmark"] = checker.benchmark(args.profile)
            print(json.dumps(result))
        return

    with TemporaryDirectory(prefix="abc-keccak-c-") as scratch:
        library, flags, sources = build(args.profile, Path(scratch), args.ubsan)
        child = [sys.executable, "-B", str(__file__), args.profile, "--exercise", str(library)]
        if args.benchmark:
            child.append("--benchmark")
        report = json.loads(subprocess.check_output(child, text=True, timeout=180))
        print(json.dumps({"status": "passed", "profile": args.profile, "flags": flags,
                          "compiler": subprocess.check_output(["clang", "--version"], text=True, timeout=15).splitlines()[:2],
                          "sources_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
                          "oracle": "Independent FIPS arithmetic and XKCP" if args.profile == "keccak-p1600"
                          else ssl.OPENSSL_VERSION + " via CPython", **report}, indent=2))


if __name__ == "__main__":
    main()
