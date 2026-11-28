"""Build the Python ECDSA signing dependency and test its packaged ABI."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import runpy
import shutil
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[5]
C_LEAF = HERE.parent / "c"
RUST = HERE.parent / "rust"
NATIVE = runpy.run_path(str(C_LEAF / "check.py"))
PROVIDER = NATIVE["provider"]
LIBRARY = "abc_ecdsa_p256_sha256_c.dll"


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def exercise(rust_oracle):
    sys.path.insert(0, str(REPO))
    from cryptography import __version__ as pyca
    from cryptography.hazmat.backends.openssl.backend import backend
    import abc_ecdsa_p256 as api

    modulus = NATIVE["ORDER"]
    rng = random.Random(6979)
    rows = []
    signer = api.DeterministicSigner(os.environ["ABC_ECDSA_P256_LIBRARY"])
    for length in (0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 128, 1024):
        for _ in range(4):
            scalar = rng.randrange(1, modulus).to_bytes(32, "big")
            message = rng.randbytes(length)
            point = api.public_key(scalar)
            signature = api.sign(scalar, message)
            require(signature == signer.sign(bytearray(scalar), memoryview(message)), "explicit signer mismatch")
            require(api.verify(point, message, signature), "PyCA verification")
            require(not api.verify(point, message + b"x", signature), "PyCA accepted different message")
            rows.append((scalar, point, message, signature))

    oracle = json.loads(PROVIDER["run"](["node", "-e", NATIVE["NODE"]],
                                       input=json.dumps([[value.hex() for value in row] for row in rows])))
    for (_, point, message, _), signature in zip(rows, oracle["output"], strict=True):
        require(api.verify(point, message, bytes.fromhex(signature)), "external OpenSSL signature rejected")
    rust_exact = 0
    if rust_oracle:
        stdin = "\n".join(":".join(item.hex() for item in (scalar, message, sig))
                          for scalar, _, message, sig in rows) + "\n"
        with TemporaryDirectory(prefix="abc-ecdsa-python-rust-") as target:
            command = ["cargo", "+1.92.0", "run", "--locked", "--offline", "--release", "--quiet",
                       "--manifest-path", str(RUST / "Cargo.toml"), "--example", "ecdsa_p256_interop"]
            output = PROVIDER["run"](command, cwd=REPO, env={**os.environ, "CARGO_TARGET_DIR": target}, input=stdin)
        for (_, point, _, sig), rust in zip(rows, output.splitlines(), strict=True):
            require(rust == f"{point.hex()}:{sig.hex()}", "RustCrypto deterministic signature mismatch")
            rust_exact += 1

    _, native_openssl = PROVIDER["load"](Path(os.environ["ABC_ECDSA_P256_LIBRARY"]).parent)
    print(json.dumps({"pyca": pyca, "pyca_openssl": backend.openssl_version_text(), "native_openssl": native_openssl,
                      "node": oracle["node"],
                      "node_openssl": oracle["openssl"], "bidirectional_comparisons": len(rows),
                      "rustcrypto_exact_signatures": rust_exact}))


def qualify(library, rust_oracle):
    env = {**os.environ, "ABC_ECDSA_P256_LIBRARY": str(library)}
    test = [sys.executable, "-B", "-m", "unittest", "discover", "-s", str(HERE)]
    PROVIDER["run"](test, cwd=REPO, env=env)
    command = [sys.executable, "-B", str(__file__), "--exercise"]
    if rust_oracle:
        command.append("--rust-oracle")
    return json.loads(PROVIDER["run"](command, cwd=REPO, env=env))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    PROVIDER["options"](parser)
    parser.add_argument("--output", type=Path, help="retain the validated native libraries")
    parser.add_argument("--rust-oracle", action="store_true", help="verify exact signatures with offline RustCrypto")
    parser.add_argument("--exercise", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.exercise:
        exercise(args.rust_oracle)
        return

    sources = [C_LEAF / "abc_ecdsa_p256_sha256_c.c", C_LEAF / "ecdsa_p256_nonce.c"]
    with TemporaryDirectory(prefix="abc-ecdsa-python-native-") as scratch:
        work = Path(scratch)
        artifact, receipt = PROVIDER["build"](work, args, sources, ["-DABC_ECDSA_P256_C_BUILD_DLL"], NATIVE["SYMBOLS"])
        library = work / LIBRARY
        artifact.rename(library)
        results = qualify(library, args.rust_oracle)
        require(results["native_openssl"].split()[1] == receipt["headers"], "header and provider versions differ")
        if args.output:
            target = args.output.resolve()
            target.mkdir(parents=True, exist_ok=True)
            for file in (library, work / "libcrypto-3-x64.dll"):
                shutil.copy2(file, target / file.name)
        report = {"status": "passed", "native_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
                  "sources_sha256": {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in sources},
                  "python_sha256": hashlib.sha256((HERE / "abc_ecdsa_p256.py").read_bytes()).hexdigest(),
                  **receipt, **results}
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
