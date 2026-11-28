"""Qualify C/C++ X25519 with RFC 7748, encoded edge cases and Node/OpenSSL."""

import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import runpy
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
SUPPORT = HERE.parents[3] / "kdf/argon2id/impl/c/openssl_support.py"
provider = runpy.run_path(str(SUPPORT))
SYMBOLS = "EVP_PKEY_new_raw_private_key_ex EVP_PKEY_new_raw_public_key_ex EVP_PKEY_CTX_new_from_pkey EVP_PKEY_CTX_free EVP_PKEY_free EVP_PKEY_get_raw_public_key EVP_PKEY_derive_init EVP_PKEY_derive_set_peer EVP_PKEY_derive CRYPTO_memcmp OPENSSL_cleanse".split()


def require(value, detail):
    if not value:
        raise ValueError(detail)


def exercise(binary):
    dependency, version = provider["load"](binary.parent)
    dll = C.CDLL(str(binary))
    pub, derive = dll.abc_x25519_c_public_key, dll.abc_x25519_c_shared_secret
    pub.argtypes = [C.c_void_p, C.c_size_t] * 2
    derive.argtypes = [C.c_void_p, C.c_size_t] * 3
    pub.restype = derive.restype = C.c_int
    untouched = b"\xa5" * 34
    output = C.create_string_buffer(untouched, len(untouched))
    dest = C.byref(output, 1)

    def public(scalar):
        require(pub(scalar, 32, dest, 32) == 0, "public key status")
        require(output.raw[0] == output.raw[-1] == 0xa5, "public key guard bytes")
        return output.raw[1:-1]

    def shared(scalar, peer):
        require(derive(scalar, 32, peer, 32, dest, 32) == 0, "shared secret status")
        require(output.raw[0] == output.raw[-1] == 0xa5, "shared secret guard bytes")
        return output.raw[1:-1]

    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    apr, bpr = public(alice), public(bob)
    require(apr.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "Alice RFC public key")
    require(bpr.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", "Bob RFC public key")
    require(shared(alice, bpr).hex() == shared(bob, apr).hex() ==
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "RFC agreement")
    scalar = peer = b"\x09" + bytes(31)
    for iteration in range(1000):
        scalar, peer = shared(scalar, peer), scalar
        if iteration == 0:
            require(scalar.hex() == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", "RFC first iteration")
    require(scalar.hex() == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", "RFC 1000 iterations")

    field = (1 << 255) - 19
    low_order = [number.to_bytes(32, "little") for number in (0, 1, field - 1, field, field + 1)]
    low_order.extend(bytes.fromhex(wire) for wire in (
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"))
    output.raw = untouched
    for peer in low_order:
        for candidate in (peer, peer[:-1] + bytes([peer[-1] | 0x80])):
            require(derive(alice, 32, candidate, 32, dest, 32) == 2 and output.raw == untouched, "low-order rejection")
    require(derive(alice, 32, bpr, 31, dest, 32) == 1 and output.raw == untouched, "invalid peer width")
    require(pub(alice, 31, dest, 32) == 1 and output.raw == untouched, "invalid private width")
    require(pub(alice, 32, dest, 31) == 1 and output.raw == untouched, "short destination")
    for i in range(32):
        clamped = bytes([(alice[0] & 0xf8) | (i & 7)]) + alice[1:-1] + bytes([(alice[-1] & 0x3f) | ((i >> 3) << 6)])
        require(public(clamped) == apr, "private clamping aliases")
    alias = C.create_string_buffer(alice, 32)
    require(derive(alias, 32, bpr, 32, alias, 32) == 0 and alias.raw == shared(alice, bpr), "aliased destination")

    oracle = runpy.run_path(str(HERE.parent / "java/check.py"))["reference"]()
    for row in oracle["output"]:
        scalar, peer, expected_public, expected_shared = (bytes.fromhex(field) for field in row.split(":"))
        require(public(scalar) == expected_public and shared(scalar, peer) == expected_shared, "OpenSSL interface comparison")
    print(json.dumps({"provider": version, "node": oracle["node"], "node_openssl": oracle["openssl"], "rfc_known_answers": 6,
                      "comparison_cases": len(oracle["output"]), "low_order_rejections": 14, "private_clamp_aliases": 32}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("c", "cpp"), default="c")
    parser.add_argument("--exercise", type=Path, help=argparse.SUPPRESS)
    provider["options"](parser)
    args = parser.parse_args()
    if args.exercise:
        exercise(args.exercise)
        return
    cpp = args.language == "cpp"
    leaf = HERE.parent / args.language
    source = leaf / ("x25519.cpp" if cpp else "abc_x25519_c.c")
    sources = [source, leaf / "tests.cpp"] if cpp else [source]
    with TemporaryDirectory(prefix="abc-x25519-openssl-") as scratch:
        binary, qualification = provider["build"](Path(scratch), args, sources, ["-DABC_X25519_C_BUILD_DLL"], SYMBOLS, cpp)
        report = json.loads(provider["run"]([sys.executable, "-B", str(__file__), "--exercise", str(binary)]))
        require(report["provider"].split()[1] == qualification["headers"], "header and provider versions differ")
        print(json.dumps({"status": "passed", "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                          **qualification, **report}, indent=2))


if __name__ == "__main__":
    main()
