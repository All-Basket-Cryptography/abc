"""Build a pinned AWS-LC archive offline for the Windows x64 C research check."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile


ARCHIVE = "aws-lc-sys-0.44.0.crate"
ARCHIVE_SHA256 = "f09fae7be8bb3174e05c6afdb34199e6dc0c7c04ba9fa237b1967adfbde27483"
CRATE_REVISION = "f464440d1fd3983ce9fb023e9eaf1698530919a2"
AWS_LC_VERSION = "5.5.0"


def fingerprint(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def cached_archive():
    cargo = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    candidates = sorted((cargo / "registry/cache").glob(f"*/{ARCHIVE}"))
    for path in candidates:
        if fingerprint(path) == ARCHIVE_SHA256:
            return path
    raise FileNotFoundError(f"Pass the pinned local {ARCHIVE} with --archive")


def run(args, cwd, *, input_text=None, timeout=120):
    result = subprocess.run([str(argument) for argument in args], cwd=cwd, text=True,
                            input=input_text, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def build_provider(archive, output, cmake, ninja, compiler):
    archive = (archive or cached_archive()).resolve()
    if fingerprint(archive) != ARCHIVE_SHA256:
        raise ValueError("AWS-LC source archive SHA-256 did not match the pin")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as upstream:
        upstream.extractall(output, filter="data")
    source = output / "aws-lc-sys-0.44.0/aws-lc"
    build = output / "build"
    flags = [
        "-DCMAKE_TRY_COMPILE_CONFIGURATION=Release", "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_TESTING=OFF", "-DBUILD_TOOL=OFF", "-DBUILD_LIBSSL=OFF", "-DBUILD_SHARED_LIBS=OFF",
        "-DDISABLE_GO=ON", "-DDISABLE_PERL=ON", "-DOPENSSL_NO_ASM=ON",
        "-DENABLE_SOURCE_MODIFICATION=OFF",
    ]
    run([cmake, "-S", source, "-B", build, "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={ninja}",
         f"-DCMAKE_C_COMPILER={compiler}", f"-DCMAKE_CXX_COMPILER={compiler}", *flags], output)
    run([cmake, "--build", build, "--target", "crypto", "--parallel", "4"], output, timeout=240)
    library = build / "crypto/crypto.lib"
    return {
        "archive_sha256": ARCHIVE_SHA256, "crate_revision": CRATE_REVISION, "aws_lc": AWS_LC_VERSION,
        "source": str(source), "crypto_library": str(library), "crypto_sha256": fingerprint(library),
        "cmake_flags": flags,
    }


def add_tool_arguments(parser):
    parser.add_argument("--archive", type=Path, help="pinned local AWS-LC source archive")
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--ninja", default=shutil.which("ninja") or "ninja")
    parser.add_argument("--compiler", default=shutil.which("clang-cl") or "clang-cl")


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    add_tool_arguments(cli)
    cli.add_argument("--output", type=Path, required=True, help="a new directory for the build")
    args = cli.parse_args()
    print(json.dumps(build_provider(args.archive, args.output, args.cmake, args.ninja, args.compiler), indent=2))
