"""Build and install-test local ABC Python research distributions."""

from argparse import ArgumentParser
from base64 import urlsafe_b64encode
from csv import writer
from gzip import GzipFile
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
from shutil import copyfile
import subprocess
import sys
from sysconfig import get_platform
from tarfile import PAX_FORMAT, TarInfo, open as open_tar
from tempfile import NamedTemporaryFile, TemporaryDirectory
from venv import EnvBuilder
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DIST_NAME = "abc-crypto-research"
VERSION = "0.1.0"
DIST_STEM = f"{DIST_NAME.replace('-', '_')}-{VERSION}"
DIST_INFO = f"{DIST_STEM}.dist-info"
RUST_TARGET = "x86_64-pc-windows-msvc"
WHEEL_TAG = "cp313-none-win_amd64"
PYTHON_REQUIREMENT = ">=3.13,<3.14"
SUMMARY = "ABC research bindings for portable SHA-256"
METADATA = (
    "Metadata-Version: 2.3\n"
    f"Name: {DIST_NAME}\n"
    f"Version: {VERSION}\n"
    f"Summary: {SUMMARY}\n"
    f"Requires-Python: {PYTHON_REQUIREMENT}\n"
)
CORE = "algorithms/hash/sha2/sha256/implementations/abc-rust-portable"
SOURCE_FILES = (
    f"{CORE}/Cargo.toml",
    f"{CORE}/README.md",
    f"{CORE}/src/lib.rs",
    f"{CORE}/tests/vectors.rs",
    "sdk/c/ffi/Cargo.toml",
    "sdk/c/ffi/src/lib.rs",
    "sdk/c/include/abc/abc.h",
    "sdk/python/README.md",
    "sdk/python/wheel.py",
    "sdk/python/abc_crypto/__init__.py",
    "sdk/python/tests/consumer.py",
)
WHEEL = (
    "Wheel-Version: 1.0\n"
    "Generator: abc-wheel\n"
    "Root-Is-Purelib: false\n"
    f"Tag: {WHEEL_TAG}\n"
)


def write_wheel(output: Path) -> Path:
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 13) or get_platform() != "win-amd64":
        raise ValueError("The research wheel targets 64-bit CPython 3.13 on Windows")

    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = REPO / ".abc" / "python-native"
    subprocess.run(
        [
            "cargo", "+1.92.0", "build", "--release", "--locked", "--offline",
            "--package", "abc-c-ffi", "--target", RUST_TARGET, "--target-dir", str(build),
            "--config", "target.x86_64-pc-windows-msvc.rustflags=['-C','target-feature=+crt-static']",
        ],
        cwd=REPO,
        stdout=sys.stderr,
        check=True,
    )
    native = build / RUST_TARGET / "release" / "abc_crypto.dll"
    files = {
        "abc_crypto/__init__.py": (HERE / "abc_crypto" / "__init__.py").read_bytes(),
        "abc_crypto/abc_crypto.dll": native.read_bytes(),
        f"{DIST_INFO}/METADATA": METADATA.encode("utf-8"),
        f"{DIST_INFO}/WHEEL": WHEEL.encode("utf-8"),
    }
    record_name = f"{DIST_INFO}/RECORD"
    record = StringIO(newline="")
    csv = writer(record, lineterminator="\n")
    for path, content in files.items():
        digest = urlsafe_b64encode(sha256(content).digest()).rstrip(b"=").decode("ascii")
        csv.writerow((path, f"sha256={digest}", len(content)))
    csv.writerow((record_name, "", ""))
    files[record_name] = record.getvalue().encode("utf-8")

    wheel = output / f"{DIST_STEM}-{WHEEL_TAG}.whl"
    with NamedTemporaryFile(dir=output, prefix=".abc-wheel-", delete=False) as handle:
        temporary = Path(handle.name)
    try:
        with ZipFile(temporary, "w") as archive:
            for path, content in files.items():
                info = ZipInfo(path)
                info.external_attr = 0o644 << 16
                archive.writestr(info, content, compress_type=ZIP_DEFLATED)
        temporary.replace(wheel)
    finally:
        temporary.unlink(missing_ok=True)
    return wheel


def _normalized_tar_entry(entry: TarInfo) -> TarInfo:
    entry.uid = entry.gid = entry.mtime = 0
    entry.uname = entry.gname = ""
    entry.mode = 0o755 if entry.isdir() else 0o644
    return entry


def write_sdist(output: Path) -> Path:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sdist = output / f"{DIST_STEM}.tar.gz"
    with TemporaryDirectory(dir=output, prefix=".abc-sdist-") as staging:
        staging = Path(staging)
        source_tree = staging / DIST_STEM
        for relative in SOURCE_FILES:
            destination = source_tree / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            copyfile(REPO / relative, destination)
        (source_tree / "Cargo.toml").write_text(
            f'[workspace]\nmembers = ["{CORE}", "sdk/c/ffi"]\nresolver = "2"\n',
            encoding="utf-8",
            newline="\n",
        )
        subprocess.run(
            ["cargo", "+1.92.0", "generate-lockfile", "--offline"],
            cwd=source_tree,
            stdout=sys.stderr,
            check=True,
        )
        (source_tree / "pyproject.toml").write_text(
            '[build-system]\nrequires = []\nbuild-backend = "wheel"\nbackend-path = ["sdk/python"]\n\n'
            f'[project]\nname = "{DIST_NAME}"\nversion = "{VERSION}"\n'
            f'requires-python = "{PYTHON_REQUIREMENT}"\ndescription = "{SUMMARY}"\n',
            encoding="utf-8",
            newline="\n",
        )
        (source_tree / "PKG-INFO").write_text(METADATA, encoding="utf-8", newline="\n")
        temporary = staging / sdist.name
        with temporary.open("wb") as target, GzipFile(filename="", fileobj=target, mode="wb", mtime=0) as compressed:
            with open_tar(fileobj=compressed, mode="w", format=PAX_FORMAT) as archive:
                archive.add(source_tree, arcname=DIST_STEM, filter=_normalized_tar_entry)
        temporary.replace(sdist)
    return sdist


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    """PEP 517 hook to build a wheel in the unpacked source distribution."""
    return write_wheel(Path(wheel_directory)).name


def build_sdist(sdist_directory, config_settings=None):
    """PEP 517 hook to export this native source closure."""
    return write_sdist(Path(sdist_directory)).name


def test_distribution(distribution: Path) -> None:
    """Install an artifact offline and run the isolated Python consumer."""
    distribution = distribution.resolve(strict=True)
    with TemporaryDirectory(dir=distribution.parent, prefix="consumer-") as directory:
        consumer = Path(directory)
        environment = consumer / ".venv"
        EnvBuilder(with_pip=True).create(environment)
        python = environment / "Scripts" / "python.exe"
        subprocess.run(
            [
                python, "-I", "-m", "pip", "--isolated", "--require-virtualenv",
                "--disable-pip-version-check", "install", "--no-index", "--no-deps",
                "--no-cache-dir", "--no-build-isolation", distribution,
            ],
            cwd=consumer,
            stdout=sys.stderr,
            check=True,
        )
        script = consumer / "verify.py"
        copyfile(HERE / "tests" / "consumer.py", script)
        subprocess.run([python, "-I", script], cwd=consumer, check=True)


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPO / ".abc" / "dist" / "python")
    parser.add_argument("--consumer-test", action="store_true")
    parser.add_argument("--sdist", action="store_true", help="also build a Python source distribution")
    parser.add_argument("--check-source", action="store_true")
    args = parser.parse_args()
    if args.check_source:
        for path in HERE.rglob("*.py"):
            compile(path.read_bytes(), str(path), "exec")
        print(json.dumps({"source_check": "passed"}))
        return
    wheel = write_wheel(args.output)
    if args.consumer_test:
        test_distribution(wheel)
    result = {
        "wheel": str(wheel),
        "sha256": sha256(wheel.read_bytes()).hexdigest(),
        "size_bytes": wheel.stat().st_size,
        "tag": WHEEL_TAG,
        "consumer_test": "passed" if args.consumer_test else "not_run",
    }
    if args.sdist:
        sdist = write_sdist(args.output)
        if args.consumer_test:
            test_distribution(sdist)
        result["sdist"] = {
            "path": str(sdist),
            "sha256": sha256(sdist.read_bytes()).hexdigest(),
            "size_bytes": sdist.stat().st_size,
            "consumer_test": "passed" if args.consumer_test else "not_run",
        }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
