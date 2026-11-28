"""Measure archived and current C/C++ scrypt builds against OpenSSL."""

import argparse
import ctypes
from hashlib import sha256, scrypt
import json
from pathlib import Path
import platform
import runpy
import ssl
from statistics import median
import subprocess
from time import perf_counter_ns


ROOT = Path(__file__).resolve().parents[2]
CHECKER = Path("src/crypto/kdf/scrypt/impl/c/check.py")
PASSWORD = bytes((41 + 131 * index) & 255 for index in range(1, 74))
SALT = bytes((71 + 11 * index) & 255 for index in range(2, 25))
LENGTH = 64
SAMPLES = 11


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def bind(binary, language):
    library = ctypes.CDLL(str(binary))
    prefix = "abc_scrypt_test_" if language == "cpp" else "abc_scrypt_c_"
    derive = getattr(library, prefix + "derive")
    pointer, size, word = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32
    derive.argtypes = [pointer, size, pointer, size, size, word, word, pointer, size, pointer, size]
    derive.restype = ctypes.c_int
    return derive


def operation(derive, n, r, p):
    space = ctypes.create_string_buffer((n + p + 1) * 128 * r)
    out = ctypes.create_string_buffer(LENGTH)

    def run():
        status = derive(PASSWORD, len(PASSWORD), SALT, len(SALT), n, r, p, space, len(space), out, LENGTH)
        if status != 0:
            raise ValueError(f"Native scrypt failed with code {status}")
        return out.raw

    return run


def measure(method, calls):
    start = perf_counter_ns()
    for _ in range(calls):
        method()
    return (perf_counter_ns() - start) / (1000 * calls)


def stats(values):
    return {"median": median(values), "min": min(values), "max": max(values), "samples": values}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("output", type=Path, help="fresh scratch directory for both builds and the receipt")
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True)
    inputs = {"baseline": args.baseline.resolve(), "candidate": ROOT}
    results = []
    builds = {}
    for language in ("c", "cpp"):
        functions = []
        for name, root in inputs.items():
            build_dir = output / f"{name}-{language}"
            build_dir.mkdir()
            build = runpy.run_path(str(root / CHECKER))["build_artifact"]
            binary, source, provider = build(args.cc, build_dir, language, False)
            builds[build_dir.name] = {"source": source.relative_to(root).as_posix(), "source_sha256": digest(source),
                                      "build_runner_sha256": digest(root / CHECKER), "binary_sha256": digest(binary),
                                      **provider}
            functions.append(bind(binary, language))
        for n, r, p, calls in ((16, 2, 3, 128), (1024, 8, 1, 16), (512, 32, 2, 8)):
            def oracle():
                return scrypt(PASSWORD, salt=SALT, n=n, r=r, p=p, dklen=LENGTH, maxmem=64 * 1024**2)

            methods = [operation(derive, n, r, p) for derive in functions] + [oracle]
            expected = oracle()
            for method in methods:
                if method() != expected:
                    raise ValueError(f"{language} scrypt disagrees with OpenSSL at {(n, r, p)}")
                measure(method, 3 * calls)
            timings = [[], [], []]
            for sample in range(SAMPLES):
                pair = (sample % 2, 1 - sample % 2)
                order = (2, *pair) if sample % 3 == 0 else (*pair, 2)
                for index in order:
                    timings[index].append(measure(methods[index], calls))
            baseline, candidate, openssl = map(stats, timings)
            results.append({"language": language, "n": n, "r": r, "p": p, "calls": calls,
                            "workspace_bytes": (n + p + 1) * 128 * r, "baseline": baseline,
                            "candidate": candidate, "openssl": openssl})
    compiler = subprocess.check_output([args.cc, "--version"], text=True).splitlines()[:2]
    report = {"platform": platform.platform(), "processor": platform.processor(),
              "compiler": compiler, "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
              "runner_sha256": digest(Path(__file__)), "samples": SAMPLES, "output_bytes": LENGTH,
              "units": "microseconds per operation", "builds": builds, "results": results}
    receipt = json.dumps(report, indent=2) + "\n"
    (output / "result.json").write_text(receipt, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
