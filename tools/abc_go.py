"""Assemble and check the Windows amd64 Go research distribution."""

import os
from pathlib import Path
import platform
import shutil
import sys
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from tools.abc_package import RUST_CHANNEL, RUST_MANIFEST, _metadata, _run


ARTIFACT = "abc-go-0.1.0-windows-amd64.zip"
FILES = {"sdk/go.mod", "sdk/README.md", "sdk/sha256_windows.go", "sdk/native/abc_crypto.dll"}


def _require_windows():
    if os.name != "nt" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise ValueError("The Go research distribution targets Windows amd64")


def package_go(repo, directory):
    _require_windows()
    _run(["cargo", f"+{RUST_CHANNEL}", "build", "--manifest-path", RUST_MANIFEST, "--target-dir", "target",
          "--locked", "--offline", "-p", "abc-c-ffi", "--release"], repo)
    directory.mkdir(parents=True, exist_ok=True)
    artifact = directory / ARTIFACT
    with ZipFile(artifact, "w", compression=ZIP_DEFLATED) as distribution:
        for name in sorted(FILES):
            if name.endswith(".dll"):
                source = repo / "target/release/abc_crypto.dll"
            else:
                source = repo / "sdk/go" / Path(name).name
            distribution.writestr(ZipInfo(name), source.read_bytes(), compress_type=ZIP_DEFLATED)
    return {"profile": "research", "sdk": "go", **_metadata(artifact.resolve())}


def check_go(repo, artifact):
    _require_windows()
    with TemporaryDirectory(prefix="abc-go-consumer-") as location:
        project = Path(location) / "consumer"
        project.mkdir()
        shutil.copyfile(repo / "compatibility/consumers/go/go.mod.in", project / "go.mod")
        shutil.copyfile(repo / "compatibility/consumers/go/main.go", project / "main.go")
        with ZipFile(artifact) as distribution:
            if sorted(distribution.namelist()) != sorted(FILES):
                raise ValueError("Go distribution file list does not match the expected layout")
            distribution.extractall(project)
        env = {**os.environ, "CGO_ENABLED": "0", "GOWORK": "off", "GOENV": "off", "GOTOOLCHAIN": "local",
               "GOPROXY": "off", "GOSUMDB": "off", "GOCACHE": str(Path(location) / "cache")}
        check = _run(["go", "run", ".", str(project / "sdk/native/abc_crypto.dll")], project, env=env).strip()
    return {"profile": "research", "sdk": "go", **_metadata(artifact.resolve()), "checks": {"go": check}}


if __name__ == "__main__":
    repo = Path(__file__).resolve().parents[1]
    with TemporaryDirectory(prefix="abc-go-check-") as location:
        env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "windows", "GOARCH": "amd64", "GOWORK": "off", "GOENV": "off",
               "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOCACHE": location}
        try:
            _run(["go", "build", "-trimpath", "./..."], repo / "sdk/go", env=env)
            print("Windows amd64 Go source compiled")
        except (OSError, ValueError) as failure:
            sys.exit(str(failure))
