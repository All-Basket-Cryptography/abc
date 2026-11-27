"""Exercise the AWS-LC C profile against pinned ACVP fixtures and OpenSSL."""

import argparse
from hashlib import sha256
import itertools
import json
import os
from pathlib import Path
from subprocess import check_output, run
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parents[1] / "spec/acvp-fips204-sample.json"
ACVP_REVISION = "975de31eb83d87039ec88934fdc47d8c312b892d"
FIXTURE_SHA256 = "5bbbc60f0975c277b128f434cec8acd44f2b28b8c00df1d5295b13ffe52fed23"
ACVP_SOURCES = {
    "sigGen": ("c090942249958e2071d56bf458b19e31256ded3e",
               "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22"),
    "sigVer": ("4c8caf12220e44dfa711fefe20e0285aaad844be",
               "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437"),
}
OK, INVALID, LENGTH, VERIFY_FAILED = 0, 1, 2, 3
PUBLIC, EXPANDED, SIG = 1952, 4032, 3309
CANARY = b"\x5a" * 16


def require(condition, description):
    if not condition:
        raise ValueError(f"{FIXTURE.name}: {description}")


def require_fields(record, fields, label):
    require(isinstance(record, dict) and record.keys() == set(fields), f"invalid {label} fields")


def decode_hex(value, byte_length, label):
    require(isinstance(value, str) and len(value) == byte_length * 2, f"invalid {label} length")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{FIXTURE.name}: invalid {label} hexadecimal data") from error
    require(len(decoded) == byte_length, f"invalid {label} byte length")
    return decoded


def load_fixture(path=FIXTURE):
    # read_text normalizes CRLF checkouts to the published LF fixture encoding.
    content = path.read_text(encoding="utf-8")
    fixture = json.loads(content)
    require_fields(fixture, ("acvp_revision", "keyGen", "sigGen", "sigVer"), "root")
    require(fixture["acvp_revision"] == ACVP_REVISION, "unexpected NIST ACVP revision")

    key_case = fixture["keyGen"]
    require_fields(key_case, ("tgId", "tcId", "seed", "public_key_sha256"), "keyGen")
    key_ids = (key_case["tgId"], key_case["tcId"])
    require(all(type(value) is int for value in key_ids) and key_ids == (2, 26),
            "keyGen must use group 2, case 26")
    key_case["seed"] = decode_hex(key_case["seed"], 32, "keyGen seed")
    key_case["public_key_sha256"] = decode_hex(key_case["public_key_sha256"], 32, "keyGen digest")

    selections = {
        "sigGen": [(41, 1, 11, None)],
        "sigVer": [(38, 1, 163, False), (43, 166, 149, True)],
    }
    for mode, selection in selections.items():
        group = fixture[mode]
        require_fields(group, ("tgId", "source_git_blob", "source_sha256", "cases"), mode)
        require(type(group["tgId"]) is int and group["tgId"] == 3, f"{mode} must use group 3")
        origin = (group["source_git_blob"], group["source_sha256"])
        require(origin == ACVP_SOURCES[mode], f"unexpected published {mode} provenance")
        cases = group["cases"]
        require(isinstance(cases, list) and len(cases) == len(selection), f"unexpected {mode} selection")
        for case, (case_id, message_length, context_length, passed) in zip(cases, selection, strict=True):
            sizes = {"message": message_length, "context": context_length, "pk": PUBLIC, "signature": SIG}
            if mode == "sigGen":
                sizes["sk"] = EXPANDED
            outcome = () if passed is None else ("testPassed",)
            label = f"{mode} case {case_id}"
            require_fields(case, ("tcId", *sizes, *outcome), label)
            require(type(case["tcId"]) is int and case["tcId"] == case_id, f"unexpected {label} selection")
            if passed is not None:
                require(case["testPassed"] is passed, f"unexpected {label} result")
            for field, length in sizes.items():
                case[field] = decode_hex(case[field], length, f"{label} {field}")

    require(sha256(content.encode("utf-8")).hexdigest() == FIXTURE_SHA256, "locked fixture digest mismatch")
    return fixture


def build(compiler, source, provider, output):
    flags = ["ABC_MLDSA65_C_SHARED", "ABC_MLDSA65_C_BUILD", "ABC_MLDSA65_C_TEST_SUPPORT"]
    if sys.platform == "win32":
        target = output / "abc_mldsa65_c_test.dll"
        command = [compiler, "/std:c17", "/MD", "/LD", "/O2", "/W4", "/WX",
                   *("/D" + flag for flag in flags), "/I" + str(source), "/I" + str(source / "include"),
                   str(HERE / "abc_mldsa65_c.c"), "/Fo:" + str(output / "wrapper.obj"), "/Fe:" + str(target),
                   "/link", str(provider), "bcrypt.lib", "advapi32.lib", "ws2_32.lib", "crypt32.lib"]
    else:
        target = output / "abc_mldsa65_c_test.so"
        command = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                   *("-D" + flag for flag in flags), "-I", str(source), "-I", str(source / "include"),
                   str(HERE / "abc_mldsa65_c.c"), str(provider), "-pthread", "-ldl", "-o", str(target)]
    run(command, check=True, timeout=90)
    return target, command


def exercise(library, openssl):
    import ctypes as C

    if not __debug__:
        raise RuntimeError("The conformance checks require Python assertions")
    fixture = load_fixture()
    native = C.CDLL(str(library))
    pointer, size = C.c_void_p, C.c_size_t

    def bind(name, arguments):
        function = getattr(native, "abc_mldsa65_c_" + name)
        function.argtypes = arguments
        function.restype = C.c_int
        return function

    key = bind("public_key", [pointer, size] * 2)
    sign = bind("sign", [pointer, size] * 4)
    verify = bind("verify", [pointer, size] * 4)
    sign_expanded = bind("sign_expanded_for_test", [pointer, pointer, size, pointer, size, pointer])

    def guarded_output(function, args, length):
        initial = b"\x00" * length + CANARY
        buffer = C.create_string_buffer(initial, len(initial))
        assert function(*args, buffer, length) == OK
        assert buffer.raw[length:] == CANARY
        return buffer.raw[:length]

    key_case = fixture["keyGen"]
    seed = key_case["seed"]
    public = guarded_output(key, (seed, len(seed)), PUBLIC)
    assert sha256(public).digest() == key_case["public_key_sha256"]
    for case in fixture["sigGen"]["cases"]:
        message, context, public_case, expanded, expected = (
            case[field] for field in ("message", "context", "pk", "sk", "signature")
        )
        output = C.create_string_buffer(SIG)
        assert sign_expanded(expanded, message, len(message), context, len(context), output) == OK
        assert output.raw == expected
        assert verify(public_case, PUBLIC, message, len(message), context, len(context), expected, SIG) == OK
    for case in fixture["sigVer"]["cases"]:
        message, context, public_case, signature = (
            case[field] for field in ("message", "context", "pk", "signature")
        )
        wanted = OK if case["testPassed"] else VERIFY_FAILED
        assert verify(public_case, PUBLIC, message, len(message), context, len(context), signature, len(signature)) == wanted

    empty_sig = guarded_output(sign, (seed, len(seed), None, 0, None, 0), SIG)
    assert verify(public, PUBLIC, None, 0, None, 0, empty_sig, SIG) == OK
    assert verify(public, PUBLIC, b"x", 1, None, 0, empty_sig, SIG) == VERIFY_FAILED
    assert verify(public, PUBLIC, None, 0, b"x", 1, empty_sig, SIG) == VERIFY_FAILED
    modified = bytes([empty_sig[0] ^ 1]) + empty_sig[1:]
    assert verify(public, PUBLIC, None, 0, None, 0, modified, SIG) == VERIFY_FAILED
    canary = C.create_string_buffer(CANARY, len(CANARY))
    assert sign(seed, 31, None, 0, None, 0, canary, SIG) == LENGTH
    assert sign(seed, 32, None, 0, None, 0, canary, SIG - 1) == LENGTH
    assert sign(seed, 32, None, 1, None, 0, canary, SIG) == INVALID
    assert sign(seed, 32, None, 0, b"x", 256, canary, SIG) == LENGTH
    assert key(seed, 32, canary, PUBLIC - 1) == LENGTH
    assert key(None, 32, canary, PUBLIC) == INVALID
    assert verify(public, PUBLIC, None, 0, None, 0, empty_sig, SIG - 1) == LENGTH
    assert verify(public, PUBLIC - 1, None, 0, None, 0, empty_sig, SIG) == LENGTH
    assert verify(public, PUBLIC, None, 0, b"x", 256, empty_sig, SIG) == LENGTH
    assert canary.raw == CANARY
    alias = C.create_string_buffer(seed + bytes(SIG - len(seed)), SIG)
    assert sign(alias, 32, None, 0, None, 0, alias, SIG) == OK
    assert alias.raw == empty_sig

    comparisons = 0
    with TemporaryDirectory(prefix="abc-mldsa-openssl-") as temporary:
        files = Path(temporary)
        (files / "seed.der").write_bytes(bytes.fromhex("3034020100300b060960864801650304031204228020") + seed)

        def reference(*args, check=True):
            return run([openssl, *args], cwd=files, check=check, capture_output=True, timeout=20)

        reference("pkey", "-inform", "DER", "-in", "seed.der", "-pubout", "-out", "pub.pem")
        reference("pkey", "-pubin", "-in", "pub.pem", "-pubout", "-outform", "DER", "-out", "pub.der")
        assert (files / "pub.der").read_bytes()[-PUBLIC:] == public
        for message, context in itertools.product(
            (b"x", bytes(range(64)), bytes(range(256)) * 4),
            (b"", b"\0\xff", bytes(range(128)), bytes(range(255))),
        ):
            context_option = ["-pkeyopt", "hexcontext-string:" + context.hex()] if context else []
            (files / "message").write_bytes(message)
            reference("pkeyutl", "-sign", "-rawin", "-inkey", "seed.der", "-keyform", "DER", "-in", "message",
                      "-out", "sign.bin", "-pkeyopt", "deterministic:1", *context_option)
            signature = guarded_output(sign, (seed, 32, message, len(message), context, len(context)), SIG)
            assert signature == (files / "sign.bin").read_bytes()
            assert verify(public, PUBLIC, message, len(message), context, len(context), signature, SIG) == OK
            (files / "sign.bin").write_bytes(signature)
            reference("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", "pub.pem", "-in", "message",
                      "-sigfile", "sign.bin", *context_option)
            comparisons += 1
        version = reference("version").stdout.decode().strip()
    return {"acvp_keygen": 1, "acvp_siggen": len(fixture["sigGen"]["cases"]),
            "acvp_sigver": len(fixture["sigVer"]["cases"]), "openssl_comparisons": comparisons,
            "openssl": version}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=os.environ.get("ABC_AWS_LC_SOURCE"))
    parser.add_argument("--crypto-library", type=Path, default=os.environ.get("ABC_AWS_LC_STATIC_LIBRARY"))
    parser.add_argument("--openssl", default=os.environ.get("ABC_OPENSSL", "openssl"))
    parser.add_argument("--cc", default="clang-cl" if sys.platform == "win32" else "clang")
    parser.add_argument("--output", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--exercise", type=Path)
    mode.add_argument("--check-fixtures", action="store_true")
    options = parser.parse_args()
    if options.check_fixtures:
        fixture = load_fixture()
        print(json.dumps({"status": "passed", "acvp_revision": ACVP_REVISION, "fixture_sha256": FIXTURE_SHA256,
                          "keyGen": [fixture["keyGen"]["tcId"]],
                          "sigGen": [case["tcId"] for case in fixture["sigGen"]["cases"]],
                          "sigVer": [case["tcId"] for case in fixture["sigVer"]["cases"]]}))
        return
    if options.exercise is not None:
        print(json.dumps(exercise(options.exercise, options.openssl)))
        return
    if options.source is None or options.crypto_library is None or options.output is None:
        parser.error("the native build requires --source, --crypto-library and --output")
    output = options.output.resolve()
    output.mkdir(exist_ok=True, parents=True)
    provider = options.crypto_library.resolve()
    provider_hash = sha256(provider.read_bytes()).hexdigest()
    library, command = build(options.cc, options.source.resolve(), provider, output)
    result = check_output([sys.executable, "-B", str(__file__), "--exercise", str(library),
                           "--openssl", options.openssl], text=True, timeout=120)
    report = {"status": "passed", "checks": json.loads(result), "command": command,
              "crypto_library_sha256": provider_hash, "fixture_sha256": FIXTURE_SHA256,
              "library_sha256": sha256(library.read_bytes()).hexdigest()}
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
