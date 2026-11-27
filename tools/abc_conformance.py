"""Test the Windows research packages in clean consumers across seven SDKs."""

from contextlib import redirect_stdout
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from tools.abc_go import _require_windows, check_go, package_go
from tools.abc_java import check_java, package_java
from tools.abc_package import _metadata, _run, consumer_test, package
from tools.abc_runner import _write_json


def check_all(repo, directory, browser=None):
    _require_windows()
    from sdk.c.package import consumer as native_consumer

    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    results = []
    for sdk in ("rust", "npm"):
        artifact = package(repo, sdk, directory)
        results.append(consumer_test(repo, sdk, Path(artifact["file"]), browser if sdk == "npm" else None))

    _run([sys.executable, "sdk/c/package.py", "--sdk", "cpp", "--output", str(directory)], repo)
    c_package = directory / "abc-c-0.1.0-x86_64-pc-windows-msvc.zip"
    cpp_package = directory / "abc-cpp-0.1.0-x86_64-pc-windows-msvc.zip"
    for sdk, package_path, components in (("c", c_package, [c_package]), ("cpp", cpp_package, [c_package, cpp_package])):
        with TemporaryDirectory(prefix=f"abc-{sdk}-consumer-") as stage:
            with redirect_stdout(sys.stderr):
                native_consumer(Path(stage), sdk, components)
        results.append({"sdk": sdk, **_metadata(package_path), "checks": {sdk: "passed"}})

    go = package_go(repo, directory)
    results.append(check_go(repo, Path(go["file"])))
    java = package_java(repo, directory)
    results.append(check_java(repo, Path(java["file"])))
    python_output = _run([sys.executable, "sdk/python/wheel.py", "--sdist", "--consumer-test", "--output", str(directory)], repo)
    python_result = json.loads(python_output[python_output.rfind("\n{") + 1:])
    wheel_path = Path(python_result["wheel"])
    results.append({"sdk": "python", **_metadata(wheel_path), "checks": {"python": python_result["consumer_test"]}})

    report = {"schema_version": 1, "profile": "research", "target": "windows-amd64", "common_vector": "nist-sha256-abc",
              "browser": "passed" if browser else "not_run", "prior_release_compatibility": "no_previous_release",
              "consumers": [{**entry, "file": Path(entry["file"]).name} for entry in results]}
    _write_json(directory / "conformance.json", report)
    return report
