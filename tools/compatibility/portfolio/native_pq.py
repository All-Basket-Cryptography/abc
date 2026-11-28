"""Build pinned AWS-LC once and replay both Windows x64 native C PQ leaves."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
from runpy import run_path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[3]
KEM = ROOT / "src/crypto/agreement/ml-kem-768"
DSA = ROOT / "src/crypto/signature/ml-dsa-65"
KEM_CHECK = KEM / "impl/c/check.py"
DSA_CHECK = DSA / "impl/c/check.py"
GIT_OPENSSL = Path("C:/Program Files/Git/mingw64/bin/openssl.exe")
LEAF_REPORTS = {"ml-kem-768": "ml-kem-768.json", "ml-dsa-65": "ml-dsa-65.json"}
INPUTS = (
    Path(__file__),
    *(KEM / "impl/c" / name for name in ("build_provider.py", "check.py", "checks.c", "ml_kem_768.c",
                                         "ml_kem_768.h", "openssl_oracle.py", "test_seeds.h")),
    KEM / "spec/acvp.json", KEM / "spec/fixtures.py",
    DSA_CHECK, DSA / "impl/c/abc_mldsa65_c.c", DSA / "impl/c/abc_mldsa65_c.h",
    DSA / "spec/acvp-fips204-sample.json",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sources():
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in INPUTS}


def command(args, timeout=120):
    return subprocess.run([str(arg) for arg in args], cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout, check=True).stdout.strip()


def executable(value):
    return Path(shutil.which(str(value)) or value).resolve(strict=True)


def write_report(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def normalize_command(args, scratch):
    return [arg.replace(str(scratch), "<work>").replace(str(ROOT), "<repo>") for arg in args]


def read_report(path):
    return json.loads(path.read_bytes())


def tool(path, version_args):
    return {"version": command([path, *version_args]).splitlines()[0], "sha256": digest(path)}


def validate_results(archive_sha, crypto_sha, providers, kem, dsa):
    require(kem["status"] == dsa["status"] == "passed", "Both native C providers must pass")
    require(kem["source_archive_sha256"] == archive_sha and
            kem["crypto_library_sha256"] == dsa["crypto_library_sha256"] == crypto_sha,
            "The two native leaves did not use the same pinned AWS-LC build")
    require(kem["openssl_library_sha256"] == providers["crypto_sha256"] and kem["openssl"] == providers["kem_version"] and
            dsa["checks"]["openssl"] == providers["cli"]["version"], "OpenSSL execution provenance differs")
    require(kem["rfc_9935"] == "passed" and kem["acvp_cases"] > 0 and kem["randomized_public_api_roundtrips"] > 0 and
            kem["independent_keygen_encap_decap_cases"] > 0 and kem["valid_length_implicit_rejection_cases"] > 0 and
            all(dsa["checks"][item] > 0 for item in ("acvp_keygen", "acvp_siggen", "acvp_sigver", "openssl_comparisons")),
            "The receipt does not cover both sets of native vectors and independent comparisons")


def replay(options, build_provider):
    machine = platform.machine().lower()
    require(sys.platform == "win32" and machine in {"amd64", "x86_64"}, "Native C PQ replay requires Windows x64")
    require(not options.output.exists(), "Choose a new native C PQ receipt directory")
    archive = (options.archive or build_provider["cached_archive"]()).resolve(strict=True)
    compiler = executable(options.compiler)
    cmake = executable(options.cmake)
    ninja = executable(options.ninja)
    openssl = executable(options.openssl)
    libcrypto = (options.openssl_crypto or openssl.with_name("libcrypto-3-x64.dll")).resolve(strict=True)
    lock = sources()
    tools = {"compiler": tool(compiler, ["--version"]), "cmake": tool(cmake, ["--version"]),
             "ninja": tool(ninja, ["--version"]), "python": platform.python_version()}
    external = {"cli": tool(openssl, ["version"]), "crypto_sha256": digest(libcrypto)}
    require(external["cli"]["version"].startswith("OpenSSL 3.5.4 "), "Expected the OpenSSL 3.5.4 CLI")
    upstream = {}
    if options.upstream:
        fixtures = run_path(str(KEM / "spec/fixtures.py"))
        fixtures["check_fixtures"](options.upstream)
        upstream = {f"{stem}-internalProjection.json": expected for stem, expected in fixtures["SOURCES"].values()}
    revision = command(["git", "rev-parse", "HEAD"])
    options.work_root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="pq-c-", dir=options.work_root) as directory:
        work = Path(directory).resolve()
        provider = build_provider["build_provider"](archive, work / "provider", cmake, ninja, compiler)
        native_kem = run_path(str(KEM_CHECK))["check_native"]
        kem = native_kem(provider, work, compiler, libcrypto, options.upstream)
        native_binaries = {name: digest(work / phase / "ml-kem-768-check.exe")
                           for name, phase in (("ml-kem-768-public", "public"), ("ml-kem-768-fixtures", "fixtures"))}
        raw_dsa = work / "dsa"
        command([sys.executable, "-B", DSA_CHECK, "--cc", compiler, "--source", provider["source"],
                 "--crypto-library", provider["crypto_library"], "--output", raw_dsa, "--openssl", openssl])
        dsa = read_report(raw_dsa / "result.json")
        dsa["command"] = normalize_command(dsa["command"], work)
        native_binaries["ml-dsa-65-fixtures"] = digest(raw_dsa / "abc_mldsa65_c_test.dll")
        require(dsa["library_sha256"] == native_binaries["ml-dsa-65-fixtures"], "ML-DSA test DLL changed before recording")
        require(digest(Path(provider["crypto_library"])) == provider["crypto_sha256"], "AWS-LC build changed during testing")
    external["kem_version"] = kem["openssl"]
    validate_results(provider["archive_sha256"], provider["crypto_sha256"], external, kem, dsa)
    require(lock == sources() and revision == command(["git", "rev-parse", "HEAD"]) and
            digest(archive) == provider["archive_sha256"] and digest(libcrypto) == external["crypto_sha256"] and
            digest(openssl) == external["cli"]["sha256"], "Native C PQ inputs changed during replay")
    for path, expected in upstream.items():
        require(digest(options.upstream / path) == expected, f"Upstream fixture changed: {path}")

    options.output.mkdir(parents=True, exist_ok=False)
    reports = {}
    for profile, result in (("ml-kem-768", kem), ("ml-dsa-65", dsa)):
        path = options.output / LEAF_REPORTS[profile]
        write_report(path, result)
        reports[profile] = digest(path)
    write_report(options.output / "result.json", {
        "schema_version": 1, "status": "passed", "scope": "native_c_post_quantum_supplement",
        "revision": revision, "input_provenance": "working_tree_sha256", "target": "windows-x64",
        "tools": tools, "sources": lock, "optional_nist_originals": upstream,
        "aws_lc": {"version": provider["aws_lc"], "crate_revision": provider["crate_revision"],
                   "source_archive_sha256": provider["archive_sha256"], "static_library_sha256": provider["crypto_sha256"],
                   "cmake_flags": provider["cmake_flags"]},
        "openssl_reference": external, "native_binaries_sha256": native_binaries, "leaf_reports_sha256": reports,
    })


def verify(directory, build_provider):
    report = read_report(directory / "result.json")
    require(report["schema_version"] == 1 and report["status"] == "passed" and report["target"] == "windows-x64" and
            report["scope"] == "native_c_post_quantum_supplement", "Unexpected native C PQ supplement receipt")
    current = sources()
    require(report["sources"] == current, "Native C PQ receipt source digests differ from this checkout")
    pinned = report["aws_lc"]
    require(pinned["source_archive_sha256"] == build_provider["ARCHIVE_SHA256"] and
            pinned["version"] == build_provider["AWS_LC_VERSION"] and pinned["crate_revision"] == build_provider["CRATE_REVISION"],
            "Native C PQ receipt AWS-LC identity differs from the repository pin")
    require(report["leaf_reports_sha256"] == {profile: digest(directory / filename)
                                               for profile, filename in LEAF_REPORTS.items()},
            "Native C PQ leaf receipt changed")
    kem = read_report(directory / LEAF_REPORTS["ml-kem-768"])
    dsa = read_report(directory / LEAF_REPORTS["ml-dsa-65"])
    require(kem["source_sha256"] == current[(KEM / "impl/c/ml_kem_768.c").relative_to(ROOT).as_posix()] and
            kem["acvp_projection_sha256"] == current[(KEM / "spec/acvp.json").relative_to(ROOT).as_posix()] and
            dsa["library_sha256"] == report["native_binaries_sha256"]["ml-dsa-65-fixtures"],
            "Native C PQ leaf identity differs from the supplement")
    validate_results(pinned["source_archive_sha256"], pinned["static_library_sha256"],
                     report["openssl_reference"], kem, dsa)


def main():
    sys.path.insert(0, str(KEM_CHECK.parent))
    build_provider = run_path(str(KEM_CHECK.parent / "build_provider.py"))
    parser = argparse.ArgumentParser(description=__doc__)
    build_provider["add_tool_arguments"](parser)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="new directory for the two leaf reports and aggregate receipt")
    mode.add_argument("--verify", type=Path, help="verify the receipt's current source and leaf-report digests")
    parser.add_argument("--openssl", default=GIT_OPENSSL if GIT_OPENSSL.is_file() else "openssl")
    parser.add_argument("--openssl-crypto", type=Path, help="OpenSSL libcrypto DLL, found next to the CLI by default")
    parser.add_argument("--upstream", type=Path, help="optional directory with the two original pinned NIST ML-KEM projections")
    parser.add_argument("--work-root", type=Path, default=ROOT / ".abc", help="short temporary build parent directory")
    options = parser.parse_args()
    try:
        directory = options.verify or options.output
        if options.output:
            replay(options, build_provider)
        verify(directory, build_provider)
    except subprocess.CalledProcessError as error:
        parser.exit(1, f"Native C PQ command exited {error.returncode}: {error.cmd}\n{error.stdout}{error.stderr}\n")
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps({"status": "verified", "receipt": str(directory / "result.json"),
                      "sha256": digest(directory / "result.json")}))


if __name__ == "__main__":
    main()
