"""Qualify the two C++ OpenSSL post-quantum modules with pinned ACVP fixtures."""

import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import runpy
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
DSA = CRYPTO / "signature/ml-dsa-65/impl/cpp"
provider = runpy.run_path(str(CRYPTO / "kdf/argon2id/impl/c/openssl_support.py"))
COMMON = "EVP_PKEY_CTX_new_from_name EVP_PKEY_CTX_free EVP_PKEY_free EVP_PKEY_fromdata_init EVP_PKEY_fromdata EVP_PKEY_keygen_init EVP_PKEY_CTX_set_params EVP_PKEY_generate EVP_PKEY_get_octet_string_param OSSL_PARAM_construct_octet_string OSSL_PARAM_construct_end".split()
SYMBOLS = {
    "kem": COMMON + "EVP_PKEY_CTX_new_from_pkey EVP_PKEY_encapsulate_init EVP_PKEY_encapsulate EVP_PKEY_decapsulate_init EVP_PKEY_decapsulate OPENSSL_cleanse".split(),
    "dsa": COMMON + "EVP_MD_CTX_new EVP_MD_CTX_free EVP_DigestSignInit_ex EVP_DigestSign EVP_DigestVerifyInit_ex EVP_DigestVerify OSSL_PARAM_construct_uint".split(),
}
CANARY = b"\xa5" * 8


def require(value, detail):
    if not value:
        raise ValueError(detail)


def bind(lib, name, *args):
    fn = getattr(lib, name)
    fn.argtypes, fn.restype = args, C.c_int
    return fn


class Guard:
    def __init__(self, size):
        self.raw = C.create_string_buffer(CANARY + bytes(size) + CANARY, size + 16)
        self.ptr = C.byref(self.raw, 8)

    def bytes(self):
        require(self.raw.raw[:8] == CANARY and self.raw.raw[-8:] == CANARY, "output guard changed")
        return self.raw.raw[8:-8]


class Bytes(C.Structure):
    _fields_ = [("data", C.c_char_p), ("size", C.c_size_t)]


def view(raw):
    return Bytes(raw or None, len(raw))


def kem(dll, vectors):
    pointer = C.c_void_p
    keygen = bind(dll, "abc_mlkem768_cpp_keygen", pointer, pointer)
    enc = bind(dll, "abc_mlkem768_cpp_encap", pointer, pointer, pointer)
    dec = bind(dll, "abc_mlkem768_cpp_decap", pointer, pointer, pointer)
    pub, priv, ct, secret, recovered = (Guard(size) for size in (1184, 2400, 1088, 32, 32))
    require(keygen(pub.ptr, priv.ptr) == 0, "random keygen")
    require(enc(pub.bytes(), ct.ptr, secret.ptr) == 0, "random encapsulation")
    require(dec(priv.bytes(), ct.bytes(), recovered.ptr) == 0 and recovered.bytes() == secret.bytes(), "round trip")
    if not vectors:
        require(not hasattr(dll, "abc_mlkem768_cpp_test_keygen") and not hasattr(dll, "abc_mlkem768_cpp_test_encap"), "test entry point leaked")
        return {"production_roundtrip": 1}

    keygen_test = bind(dll, "abc_mlkem768_cpp_test_keygen", pointer, pointer, pointer)
    enc_test = bind(dll, "abc_mlkem768_cpp_test_encap", pointer, pointer, pointer, pointer)
    cases = runpy.run_path(str(HERE.parents[1] / "spec/fixtures.py"))["check_fixtures"]()
    for case in cases:
        operation = case["operation"]
        raw = lambda field: bytes.fromhex(case[field])
        if operation == "keygen":
            require(keygen_test(raw("d") + raw("z"), pub.ptr, priv.ptr) == 0
                    and pub.bytes() == raw("ek") and priv.bytes() == raw("dk"), "ACVP keygen")
        elif operation == "encap":
            require(enc_test(raw("ek"), raw("m"), ct.ptr, secret.ptr) == 0
                    and ct.bytes() == raw("c") and secret.bytes() == raw("k"), "ACVP encapsulation")
        elif operation == "decap":
            require(dec(raw("dk"), raw("c"), secret.ptr) == 0 and secret.bytes() == raw("k"), "ACVP decapsulation")
        elif operation == "reject_dk":
            before = secret.bytes()
            require(dec(raw("dk"), bytes(1088), secret.ptr) != 0 and secret.bytes() == before, "ACVP rejected dk")
        elif operation == "reject_ek":
            before = ct.bytes(), secret.bytes()
            require(enc_test(raw("ek"), bytes(32), ct.ptr, secret.ptr) != 0
                    and (ct.bytes(), secret.bytes()) == before, "ACVP rejected ek")
        else:
            raise ValueError(f"Unknown ACVP operation {operation}")
    return {"acvp_cases": len(cases), "implicit_rejection": 1}


def dsa(dll, vectors):
    pointer = C.c_void_p
    public = bind(dll, "abc_mldsa65_cpp_public", pointer, pointer)
    sign = bind(dll, "abc_mldsa65_cpp_sign", pointer, Bytes, Bytes, pointer)
    verify = bind(dll, "abc_mldsa65_cpp_verify", pointer, Bytes, Bytes, pointer)
    pub, sig = Guard(1952), Guard(3309)
    rng = random.Random(20465)
    for length, domain_size in ((0, 0), (1, 1), (32, 255), (4097, 129)):
        seed, message, domain = rng.randbytes(32), rng.randbytes(length), rng.randbytes(domain_size)
        require(public(seed, pub.ptr) == 0, "public key derivation")
        require(sign(seed, view(message), view(domain), sig.ptr) == 0, "seed signing")
        expected = sig.bytes()
        require(sign(seed, view(message), view(domain), sig.ptr) == 0 and sig.bytes() == expected, "deterministic repeat")
        require(verify(pub.bytes(), view(message), view(domain), expected) == 0, "verify exact context")
        require(verify(pub.bytes(), view(message + b"X"), view(domain), expected) != 0, "reject altered message")
        require(sign(seed, view(message), view(bytes(256)), sig.ptr) == 1 and sig.bytes() == expected, "context bound")
    if not vectors:
        require(not hasattr(dll, "abc_mldsa65_cpp_sign_expanded"), "test entry point leaked")
        return {"production_roundtrips": 4}

    sign_expanded = bind(dll, "abc_mldsa65_cpp_sign_expanded", pointer, Bytes, Bytes, pointer)
    fixture = runpy.run_path(str(DSA.parent / "c/check.py"))["load_fixture"]()
    key = fixture["keyGen"]
    require(public(key["seed"], pub.ptr) == 0 and hashlib.sha256(pub.bytes()).digest() == key["public_key_sha256"],
            "ACVP public key SHA-256")
    for case in fixture["sigGen"]["cases"]:
        require(sign_expanded(case["sk"], view(case["message"]), view(case["context"]), sig.ptr) == 0
                and sig.bytes() == case["signature"], "ACVP deterministic signature")
        require(verify(case["pk"], view(case["message"]), view(case["context"]), sig.bytes()) == 0,
                "ACVP generated signature verifies")
    for case in fixture["sigVer"]["cases"]:
        status = verify(case["pk"], view(case["message"]), view(case["context"]), case["signature"])
        require((status == 0) == case["testPassed"], "ACVP verification outcome")
    return {"acvp_keygen": 1, "acvp_siggen": 1, "acvp_sigver": 2}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=("kem", "dsa"))
    parser.add_argument("--exercise", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--vectors", action="store_true", help=argparse.SUPPRESS)
    provider["options"](parser)
    args = parser.parse_args()
    if args.exercise:
        dependency, version = provider["load"](args.exercise.parent)
        lib = C.CDLL(str(args.exercise))
        check = kem if args.profile == "kem" else dsa
        print(json.dumps({"provider": version, **check(lib, args.vectors)}))
        return

    leaf, source, macro = ((HERE, "ml_kem_768.cpp", "ABC_MLKEM768_TESTING") if args.profile == "kem"
                           else (DSA, "ml_dsa_65.cpp", "ABC_MLDSA65_TESTING"))
    source = leaf / source
    report = {}
    for vectors in (False, True):
        with TemporaryDirectory(prefix="abc-pq-cpp-openssl-") as scratch:
            binary, qualification = provider["build"](Path(scratch), args, [source, leaf / "tests.cpp"],
                                                       [f"-D{macro}"] if vectors else [], SYMBOLS[args.profile], True)
            command = [sys.executable, "-B", str(__file__), args.profile, "--exercise", str(binary)]
            if vectors:
                command.append("--vectors")
            result = json.loads(provider["run"](command))
            require(result["provider"].split()[1] == qualification["headers"], "header and provider versions differ")
            report.update(qualification)
            report.update(result)
    print(json.dumps({"status": "passed", "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), **report}, indent=2))


if __name__ == "__main__":
    main()
