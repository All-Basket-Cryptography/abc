"""Build the pinned native C provider and run ML-KEM-768 conformance checks."""

import argparse
import base64
import codecs
import hashlib
import json
from pathlib import Path
import platform
import re
from runpy import run_path
from tempfile import TemporaryDirectory

from build_provider import add_tool_arguments, build_provider, fingerprint, run
from openssl_oracle import Oracle


HERE = Path(__file__).resolve().parent
SPEC = HERE.parents[1] / "spec"
REPO = HERE.parents[5]
OPENSSL = Path("C:/Program Files/Git/mingw64/bin/libcrypto-3-x64.dll")
LINK_LIBRARIES = ["advapi32.lib", "crypt32.lib", "bcrypt.lib", "ws2_32.lib"]


def trace_binary(work, provider, compiler, deterministic):
    work.mkdir()
    flags = ["/nologo", "/std:c17", "/O2", "/MD", "/W4", "/WX", "/c", f"/I{provider['source']}/include"]
    if deterministic:
        flags.append("/DABC_ML_KEM_768_TESTING")
    objects = []
    for filename in ("ml_kem_768", "checks"):
        obj = f"{filename}.obj"
        run([compiler, *flags, HERE / f"{filename}.c", f"/Fo{obj}"], work)
        objects.append(obj)
    binary = work / "ml-kem-768-check.exe"
    run([compiler, "/nologo", "/MD", *objects, provider["crypto_library"], *LINK_LIBRARIES, f"/Fe{binary}"], work)
    return binary


def trace(binary, lines):
    output = run([binary], binary.parent, input_text="\n".join(lines) + "\n")
    rows = [line.split() for line in output.splitlines()]
    if len(rows) != len(lines):
        raise ValueError("Unexpected number of C trace results")
    return rows


def check_acvp(binary, cases):
    lines = []
    expected = []
    for case in cases:
        op = case["operation"]
        if op == "keygen":
            lines.append(f"keygen {case['d'] + case['z']}")
            expected.append(["0", case["ek"], case["dk"]])
        elif op == "encap":
            lines.append(f"encap {case['ek']} {case['m']}")
            expected.append(["0", case["c"], case["k"]])
        elif op == "decap":
            lines.append(f"decap {case['dk']} {case['c']}")
            expected.append(["0", case["k"]])
        elif op == "reject_dk":
            lines.append(f"decap {case['dk']} {'00' * 1088}")
            expected.append(["2"])
        elif op == "reject_ek":
            lines.append(f"encap {case['ek']} {'00' * 32}")
            expected.append(["2"])
        else:
            raise ValueError(f"Unknown fixture operation {op}")
    for case, actual, wanted in zip(cases, trace(binary, lines), expected, strict=True):
        if actual != wanted:
            raise ValueError(f"NIST ACVP mismatch in group {case['tgId']} case {case['tcId']}")


def embedded_rfc_keys(provider):
    text = (Path(provider["source"]) / "crypto/evp_extra/p_kem_test.cc").read_text(encoding="utf-8")
    for name, raw_size in (("mlkem_768_pub_pem_str", 1184), ("mlkem_768_priv_expanded_pem_str", 2400)):
        literal = re.search(r"const char \*" + name + r"\s*=\s*(.*?);", text, re.S)
        if literal is None:
            raise ValueError(f"AWS-LC RFC 9935 fixture {name} is missing")
        pem = codecs.decode("".join(re.findall(r'"([^"]*)"', literal[1])), "unicode_escape")
        der = base64.b64decode("".join(pem.splitlines()[1:-1]), validate=True)
        yield der[-raw_size:]


def compare_with_openssl(binary, provider, oracle):
    rfc_keygen = bytes(range(64))
    seeds = [rfc_keygen, *(hashlib.sha512(f"ABC ML-KEM fixture {i}".encode()).digest() for i in range(7))]
    rfc_expected = list(embedded_rfc_keys(provider))
    for index, seed in enumerate(seeds):
        message = hashlib.sha256(b"ABC ML-KEM public fixture" + seed).digest()
        with oracle.keypair(seed) as key:
            ek = oracle.raw(key, b"pub", 1184)
            dk = oracle.raw(key, b"priv", 2400)
            ciphertext, shared = oracle.encapsulate(key, message)
            changed = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
            rejected = hashlib.shake_256(seed[32:] + changed).digest(32)
            actual = trace(binary, [
                f"keygen {seed.hex()}", f"encap {ek.hex()} {message.hex()}",
                f"decap {dk.hex()} {ciphertext.hex()}", f"decap {dk.hex()} {changed.hex()}",
            ])
            reference = [
                ["0", ek.hex(), dk.hex()], ["0", ciphertext.hex(), shared.hex()],
                ["0", shared.hex()], ["0", rejected.hex()],
            ]
            if actual != reference or oracle.decapsulate(key, ciphertext) != shared or \
                    oracle.decapsulate(key, changed) != rejected:
                raise ValueError(f"AWS-LC versus OpenSSL provider mismatch at fixture {index}")
            if index == 0 and [ek, dk] != rfc_expected:
                raise ValueError("RFC 9935 ML-KEM-768 raw key mismatch")
    return len(seeds)


def check_native(provider, work, compiler, openssl, upstream):
    cases = run_path(str(SPEC / "fixtures.py"))["check_fixtures"](upstream)
    oracle = Oracle(openssl.resolve())
    production = trace_binary(work / "public", provider, compiler, False)
    for row in trace(production, ["random"] * 4):
        if row[0] != "0":
            raise ValueError("Randomized C public API failed")
    deterministic = trace_binary(work / "fixtures", provider, compiler, True)
    check_acvp(deterministic, cases)
    count = compare_with_openssl(deterministic, provider, oracle)
    return {
        "status": "passed", "platform": platform.platform(), "compiler": run([compiler, "--version"], work).splitlines()[0],
        "aws_lc": provider["aws_lc"], "source_archive_sha256": provider["archive_sha256"],
        "crypto_library_sha256": provider["crypto_sha256"], "openssl": oracle.version,
        "openssl_library_sha256": fingerprint(openssl), "acvp_cases": len(cases), "rfc_9935": "passed",
        "independent_keygen_encap_decap_cases": count, "valid_length_implicit_rejection_cases": count,
        "randomized_public_api_roundtrips": 4,
        "source_sha256": fingerprint(HERE / "ml_kem_768.c"),
        "acvp_projection_sha256": fingerprint(SPEC / "acvp.json"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    add_tool_arguments(parser)
    parser.add_argument("--openssl-crypto", type=Path, default=OPENSSL)
    parser.add_argument("--upstream", type=Path, help="directory containing the pinned original ACVP files")
    parser.add_argument("--work-root", type=Path, default=REPO / ".abc",
                        help="directory in which to create a short temporary build path")
    options = parser.parse_args()
    options.work_root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="kem-", dir=options.work_root) as temporary:
        work = Path(temporary)
        upstream = build_provider(options.archive, work / "provider", options.cmake, options.ninja, options.compiler)
        report = check_native(upstream, work, options.compiler, options.openssl_crypto, options.upstream)
    print(json.dumps(report, indent=2))
