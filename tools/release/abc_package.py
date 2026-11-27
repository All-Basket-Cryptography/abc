"""Build research packages and exercise them in clean external projects."""

from functools import partial
from hashlib import sha256
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from tempfile import TemporaryDirectory
from threading import Thread


RUST_CHANNEL = "1.92.0"
RUST_MANIFEST = "tools/build/rust/Cargo.toml"
NPM_NAME = "abc-cryptography-research"
RUST_NAME = "abc-sha256"
WASM_TARGET = "wasm32-unknown-unknown"


def _run(argv, cwd, timeout=180, **kwargs):
    try:
        process = subprocess.run(argv, cwd=cwd, text=True, encoding="utf-8", errors="replace", capture_output=True,
                                 timeout=timeout, **kwargs)
    except FileNotFoundError as error:
        raise ValueError(f"Missing required tool {argv[0]}") from error
    if process.returncode != 0:
        raise ValueError(f"{argv[0]} failed with exit {process.returncode}\n{process.stdout}{process.stderr}")
    return process.stdout


def _archive_members(path):
    with tarfile.open(path, "r:gz") as archive:
        return {member.name for member in archive.getmembers() if member.isfile()}


def _validate_artifact(sdk, artifact):
    if sdk == "rust":
        prefix = artifact.stem.replace(".crate", "") + "/"
        files = {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", "README.md", "src/lib.rs", "tests/vectors.rs"}
    else:
        prefix = "package/"
        files = {"package.json", "README.md", "index.js", "index.d.ts", "abc_sha256.wasm"}
    members = _archive_members(artifact)
    if sdk == "rust":
        members.discard(prefix + ".cargo_vcs_info.json")
    if members != {prefix + file for file in files}:
        raise ValueError(f"Unexpected archive manifest: {sorted(members)}")


def _wasm_toolchain(repo):
    for channel in (RUST_CHANNEL, "stable"):
        try:
            version = _run(["rustup", "run", channel, "rustc", "-Vv"], repo)
            targets = _run(["rustup", "target", "list", "--installed", "--toolchain", channel], repo)
        except ValueError:
            continue
        if f"release: {RUST_CHANNEL}" in version.splitlines() and WASM_TARGET in targets.splitlines():
            return channel
    raise ValueError(f"Rust {RUST_CHANNEL} with the {WASM_TARGET} target is unavailable")


def _metadata(path):
    return {"file": str(path), "sha256": sha256(path.read_bytes()).hexdigest(), "size_bytes": path.stat().st_size}


def package(repo, sdk, output, target_dir=None):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    target_dir = (target_dir or repo / "target").resolve()
    if sdk == "rust":
        _run(["cargo", f"+{RUST_CHANNEL}", "package", "--manifest-path", RUST_MANIFEST, "-p", RUST_NAME, "--target-dir", str(target_dir),
              "--locked", "--allow-dirty", "--offline"], repo)
        source = target_dir / "package/abc-sha256-0.1.0.crate"
        _validate_artifact(sdk, source)
        artifact = output / source.name
        shutil.copyfile(source, artifact)
    else:
        channel = _wasm_toolchain(repo)
        _run(["cargo", f"+{channel}", "build", "--manifest-path", RUST_MANIFEST, "-p", "abc-sha256-wasm", "--target", WASM_TARGET, "--target-dir", str(target_dir),
              "--release", "--locked", "--offline"], repo)
        npm = "npm.cmd" if os.name == "nt" else "npm"
        with TemporaryDirectory(prefix="abc-npm-build-") as location:
            stage = Path(location)
            for filename in ("package.json", "index.js", "index.d.ts", "README.md"):
                shutil.copyfile(repo / "src/crypto/hash/sha256/sdk/npm" / filename, stage / filename)
            shutil.copyfile(target_dir / WASM_TARGET / "release/abc_sha256_wasm.wasm", stage / "abc_sha256.wasm")
            result = json.loads(_run([npm, "pack", "--json", "--offline", "--ignore-scripts", "--cache", str(stage / "cache")], stage))
            source = stage / result[0]["filename"]
            _validate_artifact(sdk, source)
            artifact = output / source.name
            shutil.copyfile(source, artifact)
    return {"profile": "research", "sdk": sdk, **_metadata(artifact)}


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format, *args):
        pass


def _browser(consumer, executable):
    browser = Path(executable).resolve(strict=True)
    handler = partial(_QuietHandler, directory=consumer)
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/browser.html"
            result = _run([str(browser), "--headless", "--disable-gpu", "--disable-background-networking",
                           f"--user-data-dir={consumer / 'browser-profile'}", "--virtual-time-budget=8000",
                           "--dump-dom", url], consumer, timeout=40)
        finally:
            server.shutdown()
            thread.join()
    if '<output id="result">ABC_BROWSER_SHA256_PASS</output>' not in result:
        raise ValueError("Browser consumer did not report SHA-256 success")
    return "External browser SHA-256 consumer passed"


def consumer_test(repo, sdk, artifact, browser=None, node_benchmark=False):
    artifact = artifact.resolve(strict=True)
    _validate_artifact(sdk, artifact)
    details = {}
    with TemporaryDirectory(prefix=f"abc-{sdk}-consumer-") as location:
        project = Path(location) / "consumer"
        shutil.copytree(repo / "tools/compatibility/consumers" / sdk, project)
        if sdk == "rust":
            (project / "Cargo.toml.in").rename(project / "Cargo.toml")
            with tarfile.open(artifact, "r:gz") as archive:
                archive.extractall(project / "vendor", filter="data")
            result = _run(["cargo", f"+{RUST_CHANNEL}", "run", "--offline"], project).strip()
            checks = {"rust": result}
        else:
            npm = "npm.cmd" if os.name == "nt" else "npm"
            (project / "package.json").write_text('{"private":true}\n', encoding="utf-8")
            local_archive = project / "binding.tgz"
            shutil.copyfile(artifact, local_archive)
            _run([npm, "install", "--offline", "--no-audit", "--ignore-scripts", "--cache", str(project / "cache"),
                  "./binding.tgz"], project)
            result = _run(["node", "check.mjs"], project).strip()
            checks = {"node": result, "browser": _browser(project, browser) if browser else "not_run"}
            if node_benchmark:
                details["node_benchmark"] = json.loads(_run(["node", "bench.mjs"], project))
    return {"profile": "research", "sdk": sdk, **_metadata(artifact), "checks": checks, **details}
