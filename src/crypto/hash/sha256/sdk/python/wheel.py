"""Build and install-test local ABC Python research distributions."""

from argparse import ArgumentParser
from base64 import urlsafe_b64encode
from csv import writer
from gzip import GzipFile
from hashlib import sha256
from io import StringIO
import json
import os
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
REPO = HERE.parents[5]
DIST_NAME = "abc-crypto-research"
VERSION = "0.1.0"
DIST_STEM = f"{DIST_NAME.replace('-', '_')}-{VERSION}"
DIST_INFO = f"{DIST_STEM}.dist-info"
RUST_TARGET = "x86_64-pc-windows-msvc"
WHEEL_TAG = "cp313-cp313-win_amd64"
PYTHON_REQUIREMENT = ">=3.13,<3.14"
SUMMARY = "ABC research bindings for portable SHA-256"
METADATA = (
    "Metadata-Version: 2.4\n"
    f"Name: {DIST_NAME}\n"
    f"Version: {VERSION}\n"
    f"Summary: {SUMMARY}\n"
    f"Requires-Python: {PYTHON_REQUIREMENT}\n"
)
CORE = "src/crypto/hash/sha256/impl/rust"
NATIVE = "src/crypto/hash/sha256/sdk/python/native"
SOURCE_FILES = (
    f"{CORE}/Cargo.toml",
    f"{CORE}/README.md",
    f"{CORE}/src/lib.rs",
    f"{CORE}/tests/vectors.rs",
    f"{NATIVE}/Cargo.toml",
    f"{NATIVE}/Cargo.lock",
    f"{NATIVE}/src/lib.rs",
    "src/crypto/hash/sha256/sdk/python/README.md",
    "src/crypto/hash/sha256/sdk/python/wheel.py",
    "src/crypto/hash/sha256/sdk/python/abc_crypto/__init__.py",
    "src/crypto/hash/sha256/sdk/python/tests/consumer.py",
)


def _build_environment() -> dict[str, str]:
    environment = dict(os.environ, PYO3_PYTHON=sys.executable)
    dependency_cache = REPO / ".abc" / "pyo3-cargo"
    if dependency_cache.is_dir() and "CARGO_HOME" not in environment:
        environment["CARGO_HOME"] = str(dependency_cache)
    return environment


def _third_party_licenses() -> dict[str, bytes]:
    metadata = subprocess.check_output(
        [
            "cargo", "+1.92.0", "metadata", "--locked", "--offline", "--format-version", "1",
            "--manifest-path", f"{NATIVE}/Cargo.toml",
        ],
        cwd=REPO,
        env=_build_environment(),
    )
    licenses = {}
    for package in sorted(json.loads(metadata)["packages"], key=lambda item: item["id"]):
        if package["source"] is None:
            continue
        directory = Path(package["manifest_path"]).parent
        files = {
            path for path in directory.iterdir()
            if path.is_file() and path.name.startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE"))
        }
        if package["license_file"] is not None:
            files.add(directory / package["license_file"])
        if not files:
            raise ValueError(f"No license file found for locked dependency {package['name']}")
        for path in sorted(files):
            name = f"third-party-licenses/{package['name']}-{package['version']}/{path.name}"
            licenses[name] = path.read_bytes()
    return licenses


def _distribution_metadata(licenses: dict[str, bytes]) -> str:
    return METADATA + "".join(f"License-File: {path}\n" for path in licenses)
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
            "--manifest-path", f"{NATIVE}/Cargo.toml", "--target", RUST_TARGET, "--target-dir", str(build),
            "--config", "target.x86_64-pc-windows-msvc.rustflags=['-C','target-feature=+crt-static']",
        ],
        cwd=REPO,
        env=_build_environment(),
        stdout=sys.stderr,
        check=True,
    )
    native = build / RUST_TARGET / "release" / "_native.dll"
    licenses = _third_party_licenses()
    files = {
        "abc_crypto/__init__.py": (HERE / "abc_crypto" / "__init__.py").read_bytes(),
        "abc_crypto/_native.pyd": native.read_bytes(),
        f"{DIST_INFO}/METADATA": _distribution_metadata(licenses).encode("utf-8"),
        f"{DIST_INFO}/WHEEL": WHEEL.encode("utf-8"),
        **{f"{DIST_INFO}/licenses/{path}": content for path, content in licenses.items()},
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
    scratch = REPO / ".abc"
    scratch.mkdir(exist_ok=True)
    with TemporaryDirectory(dir=scratch, prefix="s-") as staging:
        source_tree = Path(staging) / "src"
        for relative in SOURCE_FILES:
            destination = source_tree / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            copyfile(REPO / relative, destination)
        core_workspace = source_tree / "tools/build/rust" / "Cargo.toml"
        core_workspace.parent.mkdir(parents=True)
        core_workspace.write_text(
            f'[workspace]\nmembers = ["../../../{CORE}"]\nresolver = "2"\n',
            encoding="utf-8",
            newline="\n",
        )
        subprocess.run(
            ["cargo", "+1.92.0", "vendor", "--locked", "--offline", "--manifest-path", f"{NATIVE}/Cargo.toml"],
            cwd=source_tree,
            env=_build_environment(),
            stdout=subprocess.DEVNULL,
            check=True,
        )
        config = source_tree / ".cargo" / "config.toml"
        config.parent.mkdir()
        config.write_text(
            '[source.crates-io]\nreplace-with = "vendored"\n\n[source.vendored]\ndirectory = "vendor"\n',
            encoding="utf-8",
            newline="\n",
        )
        (source_tree / "pyproject.toml").write_text(
            '[build-system]\nrequires = []\nbuild-backend = "wheel"\nbackend-path = ["src/crypto/hash/sha256/sdk/python"]\n\n'
            f'[project]\nname = "{DIST_NAME}"\nversion = "{VERSION}"\n'
            f'requires-python = "{PYTHON_REQUIREMENT}"\ndescription = "{SUMMARY}"\n',
            encoding="utf-8",
            newline="\n",
        )
        licenses = _third_party_licenses()
        for relative, content in licenses.items():
            destination = source_tree / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        (source_tree / "PKG-INFO").write_text(_distribution_metadata(licenses), encoding="utf-8", newline="\n")
        with NamedTemporaryFile(dir=output, prefix=".abc-sdist-", delete=False) as target:
            temporary = Path(target.name)
        try:
            with temporary.open("wb") as target, GzipFile(filename="", fileobj=target, mode="wb", mtime=0) as compressed:
                with open_tar(fileobj=compressed, mode="w", format=PAX_FORMAT) as archive:
                    archive.add(source_tree, arcname=DIST_STEM, filter=_normalized_tar_entry)
            temporary.replace(sdist)
        finally:
            temporary.unlink(missing_ok=True)
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
            env=dict(os.environ, CARGO_HOME=str(consumer / "cargo-cache")),
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
