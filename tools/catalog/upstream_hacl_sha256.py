"""Compile the pinned CPython HACL* C source and compare native SHA-256 outputs."""

import argparse
import ctypes
from hashlib import file_digest, sha256
import json
from pathlib import Path
import ssl
import subprocess
import tarfile
from tempfile import TemporaryDirectory


REVISION = "df793163d5821791d4e7caf88885a2c11a107986"
ARCHIVE_SHA256 = "92edb80499cb357dfb353f682d0cb870ee0a803f4457a08917c8a4124d4f9a6c"
SOURCE_PREFIX = f"cpython-{REVISION}/Modules/_hacl"
WRAPPER = r"""
#include "Hacl_Hash_SHA2.h"

__declspec(dllexport) int abc_hacl_direct(uint8_t *input, uint32_t length, uint8_t *output) {
    Hacl_Hash_SHA2_hash_256(output, input, length);
    return 0;
}

__declspec(dllexport) int abc_hacl_stream(uint8_t *input, uint32_t length, uint8_t *output) {
    Hacl_Streaming_MD_state_32 *state = Hacl_Hash_SHA2_malloc_256();
    if (state == NULL) return -1;
    uint32_t offset = 0;
    int result = 0;
    while (offset < length && result == 0) {
        uint32_t batch = length - offset < 23 ? length - offset : 23;
        result = Hacl_Hash_SHA2_update_256(state, input + offset, batch);
        offset += batch;
    }
    if (result == 0) Hacl_Hash_SHA2_digest_256(state, output);
    Hacl_Hash_SHA2_free_256(state);
    return result;
}
"""


def fingerprint(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def build(archive, output):
    if fingerprint(archive) != ARCHIVE_SHA256:
        raise ValueError("The CPython archive does not match the pinned download digest")
    output.mkdir(parents=True, exist_ok=True)
    library = (output / "abc-hacl-source-pilot.dll").resolve()
    with TemporaryDirectory(prefix="abc-hacl-source-") as stage:
        directory = Path(stage)
        with tarfile.open(archive, "r:gz") as source_archive:
            files = [entry for entry in source_archive if entry.name.startswith(SOURCE_PREFIX + "/") and entry.isfile()]
            source_archive.extractall(directory, files, filter="data")
        source = directory / SOURCE_PREFIX
        wrapper = directory / "wrapper.c"
        wrapper.write_text(WRAPPER, encoding="utf-8")
        translation_unit = source / "Hacl_Hash_SHA2.c"
        compiler = subprocess.check_output(["clang", "--version"], text=True).splitlines()[0]
        flags = ["-shared", "-O2", "-std=c11", "-H"]
        build_result = subprocess.run(["clang", *flags, "-I", source, "-I", source / "include", translation_unit, wrapper,
                                       "-o", library], cwd=directory, capture_output=True, text=True, timeout=60)
        if build_result.returncode:
            raise RuntimeError(build_result.stderr)
        inputs = {"Hacl_Hash_SHA2.c": fingerprint(translation_unit)}
        for line in build_result.stderr.splitlines():
            prefix, separator, text = line.strip().partition(" ")
            if not separator or not prefix or set(prefix) != {"."}:
                continue
            included = Path(text).resolve()
            if included.is_file() and included.is_relative_to(source):
                inputs[included.relative_to(source).as_posix()] = fingerprint(included)
    return library, compiler, flags, dict(sorted(inputs.items()))


def compare(library):
    c_api = ctypes.CDLL(str(library))
    functions = [c_api.abc_hacl_direct, c_api.abc_hacl_stream]
    for function in functions:
        function.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        function.restype = ctypes.c_int
    lengths = (0, 1, 7, 23, 31, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1024, 4096)
    vectors = [b"abc", *(bytes(position % 251 for position in range(length)) for length in lengths)]
    for data in vectors:
        expected = sha256(data).digest()
        source = ctypes.create_string_buffer(data)
        for function in functions:
            digest = (ctypes.c_ubyte * 32)()
            if function(source, len(data), digest) != 0 or bytes(digest) != expected:
                raise ValueError(f"Native C comparison failed at {len(data)} bytes using {function.__name__}")
    return len(vectors) * len(functions)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    library, compiler, flags, inputs = build(args.archive, args.output)
    report = {"cpython_revision": REVISION, "archive_sha256": ARCHIVE_SHA256, "compiler": compiler, "flags": flags,
              "source_inputs": inputs, "probe_wrapper_sha256": sha256(WRAPPER.encode()).hexdigest(), "oracle": ssl.OPENSSL_VERSION,
              "qualified_target": "x86_64-pc-windows-msvc", "checked_cases": compare(library), "library_sha256": fingerprint(library)}
    (args.output / "hacl-source-pilot.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
