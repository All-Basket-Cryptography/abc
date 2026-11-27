"""Package the Swift API with a pinned native C ABI and test it from a clean consumer."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "sdk/swift"
RUST = "+1.92.0"
TARGETS = {"aarch64-apple-darwin", "x86_64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"}


def run(command, cwd, env=None):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=240, check=False)
    output = result.stdout + result.stderr
    print(output, flush=True)
    result.check_returncode()
    return output


def native_package(work, target, staged):
    cargo_target = work / "cargo"
    output = run(["cargo", RUST, "rustc", "--manifest-path", ROOT / "build/rust/Cargo.toml",
                  "--locked", "--offline", "--release", "-p", "abc-c-ffi", "--target", target,
                  "--target-dir", cargo_target, "--", "--print", "native-static-libs"], ROOT)
    link = re.search(r"native-static-libs: ([^\r\n]+)", output)
    if not link or not re.fullmatch(r"[- a-zA-Z0-9_]+", link[1]):
        raise ValueError("Rust's native static library dependencies could not be verified")
    native = staged / "native"
    pkg_config = native / "lib/pkgconfig"
    pkg_config.mkdir(parents=True)
    shutil.copytree(ROOT / "sdk/c/include", native / "include")
    shutil.copyfile(cargo_target / target / "release/libabc_crypto.a", native / "lib/libabc_crypto.a")
    (pkg_config / "abc-crypto.pc").write_text(f'''prefix=${{pcfiledir}}/../..
libdir=${{prefix}}/lib
includedir=${{prefix}}/include

Name: ABC Crypto
Description: ABC research C ABI v1
Version: 0.1.0
Libs: -L${{libdir}} -labc_crypto {link[1]}
Cflags: -I${{includedir}}
''', encoding="utf-8", newline="\n")


def package(args):
    if sys.platform not in {"darwin", "linux"} or not all(shutil.which(tool) for tool in ("swift", "pkg-config")):
        raise ValueError("Swift package verification needs native macOS or Linux with Swift and pkg-config")
    swift_version = run(["swift", "--version"], ROOT).strip()
    compiler = run(["rustc", RUST, "--version", "--verbose"], ROOT)
    host = re.search(r"^host: (\S+)$", compiler, re.MULTILINE)
    if not host or host[1] not in TARGETS:
        raise ValueError("the pinned Rust host is outside the Swift packaging target set")
    target = host[1]
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output.resolve() / f"abc-swift-0.1.0-{target}.zip"
    with tempfile.TemporaryDirectory(prefix="abc-swift-") as temporary:
        work = Path(temporary)
        staged = work / "package"
        staged.mkdir()
        for name in ("Package.swift", "README.md"):
            shutil.copyfile(SDK / name, staged / name)
        shutil.copytree(SDK / "Sources", staged / "Sources")
        native_package(work, target, staged)
        with ZipFile(archive, "w", compression=ZIP_DEFLATED) as prepared:
            for path in sorted(staged.rglob("*")):
                if path.is_file():
                    prepared.write(path, path.relative_to(staged).as_posix())
        if args.consumer:
            installed = work / "installed"
            with ZipFile(archive) as prepared:
                prepared.extractall(installed)
            consumer = work / "consumer"
            shutil.copytree(SDK / "consumer", consumer)
            env = {**os.environ, "PKG_CONFIG_PATH": str(installed / "native/lib/pkgconfig")}
            output = run(["swift", "run", "-c", "release", "ABCExternalConsumer"], consumer, env)
            if "Swift SHA-256 external consumer passed" not in output:
                raise RuntimeError("the external Swift consumer did not confirm execution")
    return {"profile": "research", "target": target, "swift": swift_version, "consumer_run": args.consumer,
            "archive": archive.name, "archive_sha256": sha256(archive.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/swift")
    args = parser.parse_args()
    try:
        encoded = json.dumps(package(args), indent=2) + "\n"
        if output := os.environ.get("ABC_TASK_OUTPUT"):
            (Path(output) / "swift-artifacts.json").write_text(encoded, encoding="utf-8", newline="\n")
        print(encoded, flush=True)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Swift packaging failed: {error}\n")


if __name__ == "__main__":
    main()
