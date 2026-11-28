"""Build and check the pinned native C SHA-256 core."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import re
import ssl
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
UPSTREAM = HERE / "upstream"
DIGEST_BYTES = 32
MAX_MESSAGE_BYTES = (1 << 61) - 1
OK = 0
INVALID_ARGUMENT = 1
MESSAGE_TOO_LONG = 2


def fingerprint(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def verify_upstream(archive, hacl_source):
    pin = json.loads((UPSTREAM / "source.json").read_text(encoding="utf-8"))
    files = {**pin["files"], "LICENSE-HACL": pin["hacl_license"]}
    for relative, expected in files.items():
        require(fingerprint(UPSTREAM / relative) == expected["sha256"], f"Upstream source changed: {relative}")
    if archive is not None:
        require(fingerprint(archive) == pin["cpython_archive_sha256"], "CPython archive checksum mismatch")
        prefix = f'cpython-{pin["cpython_revision"]}/'
        with tarfile.open(archive, "r:gz") as upstream:
            for relative, expected in pin["files"].items():
                member = upstream.extractfile(prefix + expected["path"])
                require(member is not None and member.read() == (UPSTREAM / relative).read_bytes(),
                        f"Archive member differs from checkout: {relative}")
    if hacl_source is not None:
        require(fingerprint(hacl_source) == pin["hacl_sha2_source"]["sha256"], "HACL* C source checksum mismatch")
        transformed = re.sub(rb'#include[^\n]*Hacl_Krmllib.h"', b"", hacl_source.read_bytes())
        transformed = re.sub(rb"[^\S\n]+(?=\n|\Z)", b"", transformed)
        require(transformed == (UPSTREAM / "Hacl_Hash_SHA2.c").read_bytes(),
                "The CPython refresh transformations did not reproduce the C translation unit")
    return pin


def build(compiler, output):
    output.mkdir(parents=True, exist_ok=True)
    extension = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
    library = (output / f"abc_sha256_c{extension}").resolve()
    flags = ["-std=c11", "-O2", "-fvisibility=hidden"]
    if sys.platform != "win32":
        flags.append("-fPIC")
    includes = ["-I", str(UPSTREAM), "-I", str(UPSTREAM / "include")]
    adapter_flags = ["-Wall", "-Wextra", "-Werror", "-DABC_SHA256_C_SHARED", "-DABC_SHA256_C_BUILD"]
    upstream_object = output / "hacl-sha2.o"
    adapter_object = output / "abc-sha256-c.o"
    link_kind = "-dynamiclib" if sys.platform == "darwin" else "-shared"
    commands = [
        [compiler, *flags, *includes, "-c", str(UPSTREAM / "Hacl_Hash_SHA2.c"), "-o", str(upstream_object)],
        [compiler, *flags, *includes, *adapter_flags, "-c", str(HERE / "abc_sha256_c.c"), "-o", str(adapter_object)],
        [compiler, link_kind, str(adapter_object), str(upstream_object), "-o", str(library)],
    ]
    for command in commands:
        subprocess.run(command, check=True, timeout=90)
    return library, commands


def exercise(library):
    from _hashlib import openssl_sha256

    api = ctypes.CDLL(str(library))
    functions = {
        "new": ([ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int),
        "update": ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t], ctypes.c_int),
        "digest": ([ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        "hash": ([ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p], ctypes.c_int),
        "free": ([ctypes.c_void_p], None),
    }
    for suffix, (arguments, result) in functions.items():
        function = getattr(api, f"abc_sha256_c_{suffix}")
        function.argtypes = arguments
        function.restype = result
        functions[suffix] = function
    new, update, digest, one_shot, free = (functions[name] for name in functions)
    output = (ctypes.c_ubyte * DIGEST_BYTES)()
    rng = random.Random(751)
    vectors = {
        b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        b"a" * 1_000_000: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    }
    bounds = [0, 1, 7, 23, 31, 54, 55, 56, 57, 63, 64, 65, 118, 119, 120, 121,
              127, 128, 129, 1024, 4096, 65537, 1048576]
    messages = [*vectors, *(rng.randbytes(length) for length in bounds)]
    messages.extend(rng.randbytes(rng.randrange(4097)) for _ in range(128))
    snapshots = 0
    for index, message in enumerate(messages):
        data = ctypes.create_string_buffer(message)
        expected = openssl_sha256(message).digest()
        if index < len(vectors):
            require(expected.hex() == vectors[message], f"OpenSSL known-answer mismatch for case {index}")
        require(one_shot(data if message else None, len(message), output) == OK, f"One-shot error for case {index}")
        require(bytes(output) == expected, f"One-shot digest mismatch for case {index}")
        state = ctypes.c_void_p()
        require(new(ctypes.byref(state)) == OK and state.value, "Allocation failed")
        try:
            reference = openssl_sha256()
            require(update(state, None, 0) == OK, "Empty update rejected")
            require(digest(state, output) == OK and bytes(output) == reference.digest(), "Empty stream digest mismatch")
            snapshots += 1
            offset = 0
            chunk_limit = 32 if len(message) <= 129 else 8192
            while offset < len(message):
                chunk = min(len(message) - offset, rng.randint(1, chunk_limit))
                require(update(state, ctypes.byref(data, offset), chunk) == OK, f"Update failed for case {index}")
                reference.update(message[offset:offset + chunk])
                require(digest(state, output) == OK and bytes(output) == reference.digest(),
                        f"Streaming snapshot mismatch for case {index} at {offset + chunk} bytes")
                snapshots += 1
                offset += chunk
            require(digest(state, output) == OK and bytes(output) == expected, f"Final digest mismatch for case {index}")
        finally:
            free(state)

    require(new(None) == INVALID_ARGUMENT, "NULL output accepted by new")
    require(update(None, None, 0) == INVALID_ARGUMENT, "NULL context accepted by update")
    require(digest(None, output) == INVALID_ARGUMENT, "NULL context accepted by digest")
    require(one_shot(None, 0, None) == INVALID_ARGUMENT, "NULL output accepted by one-shot")
    output[:] = bytes([0x5A] * DIGEST_BYTES)
    require(one_shot(None, 1, output) == INVALID_ARGUMENT, "Invalid source accepted")
    require(bytes(output) == bytes([0x5A] * DIGEST_BYTES), "Invalid source changed caller output")
    free(None)
    prefix = ctypes.create_string_buffer(b"a")
    suffix = ctypes.create_string_buffer(b"bc")
    state = ctypes.c_void_p()
    require(new(ctypes.byref(state)) == OK, "Allocation failed for validation checks")
    counted_length_rejection = ctypes.sizeof(ctypes.c_size_t) >= 8
    try:
        require(update(state, prefix, 1) == OK, "Prefix update failed")
        require(update(state, None, 1) == INVALID_ARGUMENT, "Invalid streaming input accepted")
        require(digest(state, None) == INVALID_ARGUMENT, "Invalid streaming output accepted")
        if counted_length_rejection:
            # These requests exceed the accepted domain before the input is read.
            require(update(state, prefix, MAX_MESSAGE_BYTES) == MESSAGE_TOO_LONG, "Cumulative overflow accepted")
            require(one_shot(prefix, MAX_MESSAGE_BYTES + 1, output) == MESSAGE_TOO_LONG, "One-shot overflow accepted")
            require(bytes(output) == bytes([0x5A] * DIGEST_BYTES), "Overflow changed caller output")
        require(update(state, suffix, 2) == OK, "Valid update after rejection failed")
        require(digest(state, output) == OK and bytes(output) == bytes.fromhex(vectors[b"abc"]),
                "Rejected requests changed streaming state")
    finally:
        free(state)
    data = bytes(range(64))
    overlap = ctypes.create_string_buffer(data)
    require(one_shot(overlap, len(data), ctypes.byref(overlap, 16)) == OK, "Overlapping output failed")
    require(overlap.raw[:64] == data[:16] + openssl_sha256(data).digest() + data[48:],
            "Overlapping output changed unexpected bytes")
    return {"known_answers": len(vectors), "one_shot_comparisons": len(messages),
            "streaming_snapshots": snapshots, "length_rejections_checked": counted_length_rejection,
            "oracle": ssl.OPENSSL_VERSION}


def check(compiler, output, archive, hacl_source):
    pin = verify_upstream(archive, hacl_source)
    library, commands = build(compiler, output)
    result = subprocess.check_output([sys.executable, "-B", str(__file__), "--exercise", str(library)],
                                     text=True, timeout=90)
    report = {
        "status": "passed",
        "cpython_revision": pin["cpython_revision"],
        "hacl_revision": pin["hacl_revision"],
        "archive_bytes_compared": archive is not None,
        "hacl_translation_unit_compared": hacl_source is not None,
        "source_manifest_sha256": fingerprint(UPSTREAM / "source.json"),
        "adapter_sha256": fingerprint(HERE / "abc_sha256_c.c"),
        "header_sha256": fingerprint(HERE / "abc_sha256_c.h"),
        "compiler": subprocess.check_output([compiler, "--version"], text=True).splitlines()[0],
        "target": subprocess.check_output([compiler, "-dumpmachine"], text=True).strip(),
        "commands": commands,
        "library_sha256": fingerprint(library),
        "checks": json.loads(result),
    }
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="clang", help="GCC- or Clang-compatible C compiler")
    parser.add_argument("--archive", type=Path, help="compare vendored bytes to the pinned CPython archive")
    parser.add_argument("--hacl-source", type=Path, help="reproduce the pinned CPython C translation unit from HACL*")
    parser.add_argument("--output", type=Path, help="retain the native library and check report")
    parser.add_argument("--exercise", type=Path, help="exercise an existing shared library")
    args = parser.parse_args()
    if args.exercise is not None:
        report = exercise(args.exercise.resolve())
    elif args.output is not None:
        report = check(args.cc, args.output.resolve(), args.archive, args.hacl_source)
    else:
        with TemporaryDirectory(prefix="abc-sha256-c-") as output:
            report = check(args.cc, Path(output), args.archive, args.hacl_source)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
