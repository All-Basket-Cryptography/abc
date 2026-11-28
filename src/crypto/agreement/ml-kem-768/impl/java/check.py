"""Check Java and Kotlin ML-KEM-768 using ACVP and OpenSSL fixtures."""

import hashlib
import json
from pathlib import Path
import random
import runpy
import sys


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
sys.path.insert(0, str(CRYPTO / "kdf/argon2id/impl/java"))
from bc_provider import main, run


OPENSSL = HERE.parent / "go/oracle.mjs"
FIXTURES = HERE.parents[1] / "spec/fixtures.py"
FIELDS = {"encap": ("ek", "m", "c", "k"), "decap": ("dk", "c", "k"), "reject_ek": ("ek",)}


def verify(invoke):
    fixture_module = runpy.run_path(str(FIXTURES))
    cases = []
    for case in fixture_module["check_fixtures"]():
        op = case["operation"]
        if op == "keygen":
            cases.append(f'keygen:{case["d"]}{case["z"]}:{case["ek"]}')
        elif op in FIELDS:
            cases.append(":".join([op, *(case[key] for key in FIELDS[op])]))
    if invoke("acvp", wire="\n".join(cases) + "\n") != str(len(cases)):
        raise ValueError("Incomplete ACVP fixture checks")

    rng = random.Random(203768)
    seeds = [bytes(range(64)).hex(), *(rng.randbytes(64).hex() for _ in range(11))]
    outputs = [line.split(":") for line in invoke("encapsulate", wire="\n".join(seeds) + "\n").splitlines()]
    inputs = []
    for seed, (_, ciphertext, _) in zip(seeds, outputs, strict=True):
        damaged = bytearray.fromhex(ciphertext)
        damaged[0] ^= 1
        inputs.append({"seed": seed, "ciphertext": ciphertext, "damaged": damaged.hex()})
    stdout, _ = run(["node", str(OPENSSL)], input=json.dumps(inputs))
    versions, _ = run(["node", "-p", "process.version + ' / OpenSSL ' + process.versions.openssl"])
    oracle = json.loads(stdout)
    decapsulate = []
    for seed, inp, (public, _, shared), ref in zip(seeds, inputs, outputs, oracle, strict=True):
        if ref["public"] != public or ref["decapsulated"] != shared:
            raise ValueError("OpenSSL and the SDK disagree on a generated valid key or secret")
        damage = bytes.fromhex(inp["damaged"])
        explicit = hashlib.shake_256(bytes.fromhex(seed)[32:] + damage).hexdigest(32)
        if ref["rejected"] != explicit or ref["rejected"] == shared:
            raise ValueError("OpenSSL failed the explicit FIPS 203 implicit-rejection computation")
        decapsulate.append(f'{seed}:{ref["ciphertext"]}:{ref["shared"]}')
        decapsulate.append(f'{seed}:{inp["damaged"]}:{ref["rejected"]}')
    if invoke("decapsulate", wire="\n".join(decapsulate) + "\n") != str(len(decapsulate)):
        raise ValueError("Incomplete independent decapsulation checks")
    return {"acvp_cases": len(cases), "acvp_sdk_cases": 3, "acvp_provider_cases": 4,
            "openssl_bidirectional": len(seeds), "implicit_rejections": len(seeds),
            "random_roundtrips": 4, "oracle": versions}


if __name__ == "__main__":
    main(HERE, "ml-kem-768", "org.allbasket.abc.agreement.mlkem768", "MlKem768", verify)
